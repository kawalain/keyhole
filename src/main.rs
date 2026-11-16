//! keyhole daemon for OPNsense. See `docs/adr/` for the design and
//! `opnsense/` for the files OPNsense needs alongside it.

const USAGE: &str = "\
usage: keyhole --lan IFACE --upstream IP:PORT [--dns IP:PORT] [--proxy IP:PORT] [--control NAME]

  --lan       LAN interface to observe and redirect on (e.g. igc1)
  --upstream  the ISP resolver every DNS query is forwarded to (ADR 0009)
  --dns       where Unbound forwards to          [127.0.0.1:5353]
  --proxy     where bypassed connections go      [127.0.0.1:8443]
  --control   harmless name for control probes   [example.com]";

// Only the FreeBSD daemon reads the parsed options.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
struct Args {
    lan: String,
    upstream: std::net::SocketAddr,
    dns: std::net::SocketAddr,
    proxy: std::net::SocketAddr,
    control: keyhole::domain::Domain,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut lan, mut upstream) = (None, None);
    let mut dns = "127.0.0.1:5353".to_owned();
    let mut proxy = "127.0.0.1:8443".to_owned();
    let mut control = "example.com".to_owned();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--lan" => lan = Some(value),
            "--upstream" => upstream = Some(value),
            "--dns" => dns = value,
            "--proxy" => proxy = value,
            "--control" => control = value,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    let addr = |name: &str, v: &str| v.parse().map_err(|_| format!("{name}: bad address {v}"));
    Ok(Args {
        lan: lan.ok_or("--lan is required")?,
        upstream: addr("--upstream", &upstream.ok_or("--upstream is required")?)?,
        dns: addr("--dns", &dns)?,
        proxy: addr("--proxy", &proxy)?,
        control: keyhole::domain::Domain::parse(&control).ok_or("--control: bad name")?,
    })
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("keyhole: {e}\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = daemon::run(args) {
        keyhole::log!("{e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "freebsd"))]
mod daemon {
    pub fn run(_: super::Args) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "the daemon runs on FreeBSD (OPNsense) only",
        ))
    }
}

#[cfg(target_os = "freebsd")]
mod daemon {
    use std::io;
    use std::net::{IpAddr, TcpListener, ToSocketAddrs, UdpSocket};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError, Sender};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread;
    use std::time::{Duration, Instant};

    use keyhole::bpf::Capture;
    use keyhole::classifier::{Outcome, Verdict};
    use keyhole::engine::{self, Engine, Probe};
    use keyhole::observer::{Observer, Signal};
    use keyhole::pf::{NatLook, PfAnchor};
    use keyhole::prober::{Prober, TcpDialer};
    use keyhole::{proxy, resolver};

    const MAX_PROBES: usize = 4;
    const STACK: usize = 64 * 1024;
    /// Upper bound on the coordinator's sleep, so expiries set from the
    /// resolver thread are not missed for long.
    const MAX_SLEEP: Duration = Duration::from_secs(60);

    enum Event {
        Signal(Signal),
        Outcome(Outcome),
    }

    type Shared = Arc<Mutex<Engine<PfAnchor>>>;

    fn lock(engine: &Shared) -> std::sync::MutexGuard<'_, Engine<PfAnchor>> {
        engine.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> io::Result<()> {
        thread::Builder::new()
            .name(name.into())
            .stack_size(STACK)
            .spawn(f)
            .map(drop)
    }

    pub fn run(args: super::Args) -> io::Result<()> {
        let table = PfAnchor::install(&args.lan, args.proxy)?;
        let engine: Shared = Arc::new(Mutex::new(Engine::new(table, engine::Config::default())));
        let (events, inbox) = mpsc::channel();

        // DNS: Unbound -> keyhole -> ISP resolver.
        let config = resolver::Config::new(args.upstream);
        let (udp, tcp) = (UdpSocket::bind(args.dns)?, TcpListener::bind(args.dns)?);
        for (name, tcp_side) in [("dns-udp", false), ("dns-tcp", true)] {
            let (engine, config) = (engine.clone(), config.clone());
            let hook = move |a: &keyhole::dns::Answer| lock(&engine).answer(a, Instant::now());
            let (udp, tcp) = (udp.try_clone()?, tcp.try_clone()?);
            spawn(name, move || {
                let result = if tcp_side {
                    resolver::serve_tcp(tcp, config, hook)
                } else {
                    resolver::serve_udp(udp, config, hook)
                };
                keyhole::log!("{name} stopped: {result:?}");
            })?;
        }

        // Bypassed connections.
        let listener = TcpListener::bind(args.proxy)?;
        let natlook = NatLook::open()?;
        spawn("proxy", move || {
            let result = proxy::serve(
                listener,
                move |s| natlook.original_dst(s),
                Default::default(),
            );
            keyhole::log!("proxy stopped: {result:?}");
        })?;

        // Evidence from the LAN.
        let mut capture = Capture::open(&args.lan)?;
        let tx = events.clone();
        spawn("observer", move || {
            let mut observer = Observer::new(Duration::from_secs(5), 4096);
            loop {
                let read = capture.read(|frame| {
                    if let Some(signal) = observer.on_frame(frame, Instant::now()) {
                        let _ = tx.send(Event::Signal(signal));
                    }
                });
                if let Err(e) = read {
                    keyhole::log!("capture failed: {e}");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        })?;

        keyhole::log!(
            "running: lan {} dns {} -> {} proxy {}",
            args.lan,
            args.dns,
            args.upstream,
            args.proxy
        );
        let prober = Arc::new(Prober::new(TcpDialer::default(), args.control));
        let running = Arc::new(AtomicUsize::new(0));
        loop {
            let timeout = lock(&engine)
                .next_wakeup()
                .map_or(MAX_SLEEP, |at| at.saturating_duration_since(Instant::now()))
                .min(MAX_SLEEP);
            let probes = match inbox.recv_timeout(timeout) {
                Ok(Event::Signal(s)) => {
                    keyhole::log!("signal {s:?}");
                    lock(&engine).signal(s, Instant::now())
                }
                Ok(Event::Outcome(o)) => {
                    keyhole::log!("probe {} -> {:?}", o.domain, o.verdict);
                    lock(&engine).outcome(o, Instant::now())
                }
                Err(RecvTimeoutError::Timeout) => lock(&engine).tick(Instant::now()),
                Err(RecvTimeoutError::Disconnected) => unreachable!("we hold a sender"),
            };
            for probe in probes {
                start_probe(probe, &prober, &running, &events);
            }
        }
    }

    fn start_probe(
        probe: Probe,
        prober: &Arc<Prober<TcpDialer>>,
        running: &Arc<AtomicUsize>,
        events: &Sender<Event>,
    ) {
        let inconclusive = |domain| {
            Event::Outcome(Outcome {
                domain,
                verdict: Verdict::Inconclusive,
            })
        };
        if running.fetch_add(1, Ordering::Relaxed) >= MAX_PROBES {
            running.fetch_sub(1, Ordering::Relaxed);
            let _ = events.send(inconclusive(probe.domain));
            return;
        }
        let (prober, slot, events) = (prober.clone(), running.clone(), events.clone());
        let spawned = spawn("probe", move || {
            let addr = probe.addr.or_else(|| resolve(&probe.domain));
            let verdict = match addr {
                Some(addr) => prober.tls(&probe.domain, addr),
                None => Verdict::Inconclusive,
            };
            slot.fetch_sub(1, Ordering::Relaxed);
            let _ = events.send(Event::Outcome(Outcome {
                domain: probe.domain,
                verdict,
            }));
        });
        if spawned.is_err() {
            running.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn resolve(domain: &keyhole::domain::Domain) -> Option<IpAddr> {
        (domain.as_str(), 443)
            .to_socket_addrs()
            .ok()?
            .find(|a| a.is_ipv4())
            .map(|a| a.ip())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    fn args(s: &str) -> Result<super::Args, String> {
        parse_args(s.split_whitespace().map(String::from))
    }

    #[test]
    fn required_options_and_defaults() {
        let a = args("--lan igc1 --upstream 168.126.63.1:53").unwrap();
        assert_eq!(a.lan, "igc1");
        assert_eq!(a.dns.to_string(), "127.0.0.1:5353");
        assert_eq!(a.proxy.to_string(), "127.0.0.1:8443");
        assert_eq!(a.control.as_str(), "example.com");
        assert!(args("--lan igc1").is_err());
        assert!(args("--upstream 168.126.63.1:53").is_err());
        assert!(args("--lan igc1 --upstream nope").is_err());
        assert!(args("--lan igc1 --upstream 1.1.1.1:53 --bogus x").is_err());
    }
}
