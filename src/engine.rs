//! The daemon's decisions in one place: DNS answers, observer signals and
//! probe outcomes go in; the bypass address table and probe requests come
//! out. Time and the table are injected, so the whole flow is testable.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::classifier::{self, Action, Classifier, Evidence, Outcome};
use crate::dns::{Answer, RCODE_NXDOMAIN};
use crate::domain::Domain;
use crate::observer::Signal;

/// Where `warning.or.kr` resolves (ADR 0002): an answer pointing here is
/// DNS tampering, which ADR 0009 says to log.
const BLOCK_PAGE: IpAddr = IpAddr::V4(Ipv4Addr::new(121, 189, 57, 82));

/// The set of addresses whose connections take the bypass. The pf adapter
/// lives in [`crate::pf`].
pub trait Table {
    fn add(&mut self, addrs: &[IpAddr]) -> io::Result<()>;
    fn remove(&mut self, addrs: &[IpAddr]) -> io::Result<()>;
}

/// A probe the caller must run and report with [`Engine::outcome`]. `addr`
/// is `None` when no address is known; the caller resolves the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub domain: Domain,
    pub addr: Option<IpAddr>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub classifier: classifier::Config,
    /// How long an address outlives its DNS TTL, since Unbound may hand out
    /// expired records and clients keep connections open.
    pub grace: Duration,
    /// Upper bound on remembered (address, domain) pairs.
    pub max_names: usize,
    /// Upper bound on candidate domains for one unnamed signal.
    pub max_candidates: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            classifier: classifier::Config::default(),
            grace: Duration::from_secs(600),
            max_names: 16384,
            max_candidates: 4,
        }
    }
}

/// One remembered DNS answer record.
struct Name {
    domain: Domain,
    addr: IpAddr,
    expires: Instant,
}

pub struct Engine<T> {
    config: Config,
    classifier: Classifier,
    table: T,
    /// Recent answers, oldest first.
    names: Vec<Name>,
    /// Table contents: address, the bypassed domain it was added for, and
    /// when it expires.
    entries: HashMap<IpAddr, (Domain, Instant)>,
}

impl<T: Table> Engine<T> {
    pub fn new(table: T, config: Config) -> Self {
        Self {
            classifier: Classifier::new(config.classifier.clone()),
            config,
            table,
            names: Vec::new(),
            entries: HashMap::new(),
        }
    }

    /// Records an answer from the ISP resolver. Must run before the answer
    /// reaches the client: a bypassed domain's addresses enter the table
    /// first.
    pub fn answer(&mut self, answer: &Answer, now: Instant) {
        let Some(domain) = &answer.domain else { return };
        if answer.addrs.contains(&BLOCK_PAGE) {
            crate::log!("dns: {domain} resolved to the block page (DNS tampering)");
        } else if answer.rcode == RCODE_NXDOMAIN && self.names.iter().any(|n| &n.domain == domain) {
            crate::log!("dns: {domain} became NXDOMAIN after resolving before");
        }
        let expires = now + Duration::from_secs(answer.ttl.unwrap_or(0).into()) + self.config.grace;
        for &addr in &answer.addrs {
            self.remember(domain, addr, expires, now);
        }
        if self.classifier.strategy(domain).is_some() {
            self.bypass_addrs(domain, &answer.addrs, expires);
        }
    }

    /// Feeds an observer signal.
    pub fn signal(&mut self, signal: Signal, now: Instant) -> Vec<Probe> {
        let (server, name, http) = match signal {
            Signal::TlsReset { server, sni } => (server, sni, false),
            Signal::HttpBlock { server, host } => (server, host, true),
        };
        let candidates = match name {
            Some(domain) => vec![domain],
            None => self.domains_at(server, now),
        };
        let mut actions = Vec::new();
        for domain in candidates {
            if self.classifier.strategy(&domain).is_some() {
                // Already bypassed: the client reached an address the table
                // lacks, e.g. through its own DoH.
                let expires = now + self.config.grace;
                self.bypass_addrs(&domain, &[server], expires);
                continue;
            }
            let evidence = if http {
                Evidence::HttpBlockRedirect {
                    domain,
                    addr: server,
                }
            } else {
                Evidence::SniReset {
                    domain,
                    addr: server,
                }
            };
            actions.extend(self.classifier.observe(evidence, now));
        }
        self.carry_out(actions, now)
    }

    /// Feeds the result of a probe this engine asked for.
    pub fn outcome(&mut self, outcome: Outcome, now: Instant) -> Vec<Probe> {
        let actions = self.classifier.record(outcome, now);
        self.carry_out(actions, now)
    }

    /// Advances time; call at [`Engine::next_wakeup`].
    pub fn tick(&mut self, now: Instant) -> Vec<Probe> {
        let expired: Vec<IpAddr> = self
            .entries
            .iter()
            .filter(|(_, (_, expires))| *expires <= now)
            .map(|(addr, _)| *addr)
            .collect();
        if !expired.is_empty() {
            for addr in &expired {
                self.entries.remove(addr);
            }
            report(self.table.remove(&expired));
        }
        let actions = self.classifier.tick(now);
        self.carry_out(actions, now)
    }

    pub fn next_wakeup(&self) -> Option<Instant> {
        let table = self.entries.values().map(|(_, expires)| *expires).min();
        match (table, self.classifier.next_wakeup()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn carry_out(&mut self, actions: Vec<Action>, now: Instant) -> Vec<Probe> {
        let mut probes = Vec::new();
        for action in actions {
            match action {
                Action::Probe { domain, addr } => {
                    let addr = addr.or_else(|| self.addrs_of(&domain, now).first().copied());
                    probes.push(Probe { domain, addr });
                }
                Action::Apply { domain, strategy } => {
                    crate::log!("bypass {domain} with {strategy:?}");
                    let known: Vec<_> = self
                        .names
                        .iter()
                        .filter(|n| n.domain == domain && n.expires > now)
                        .map(|n| (n.addr, n.expires))
                        .collect();
                    for (addr, expires) in known {
                        self.bypass_addrs(&domain, &[addr], expires);
                    }
                }
                Action::Lift { domain, strategy } => {
                    crate::log!("lift {strategy:?} from {domain}");
                    let addrs: Vec<IpAddr> = self
                        .entries
                        .iter()
                        .filter(|(_, (d, _))| *d == domain)
                        .map(|(addr, _)| *addr)
                        .collect();
                    for addr in &addrs {
                        self.entries.remove(addr);
                    }
                    if !addrs.is_empty() {
                        report(self.table.remove(&addrs));
                    }
                }
            }
        }
        probes
    }

    fn bypass_addrs(&mut self, domain: &Domain, addrs: &[IpAddr], expires: Instant) {
        let mut new = Vec::new();
        for &addr in addrs {
            let entry = self.entries.entry(addr).or_insert_with(|| {
                new.push(addr);
                (domain.clone(), expires)
            });
            entry.1 = entry.1.max(expires);
        }
        if !new.is_empty() {
            report(self.table.add(&new));
        }
    }

    fn remember(&mut self, domain: &Domain, addr: IpAddr, expires: Instant, now: Instant) {
        self.names
            .retain(|n| !(n.addr == addr && &n.domain == domain));
        if self.names.len() >= self.config.max_names {
            self.names.retain(|n| n.expires > now);
            if self.names.len() >= self.config.max_names {
                self.names.remove(0);
            }
        }
        self.names.push(Name {
            domain: domain.clone(),
            addr,
            expires,
        });
    }

    /// Domains that recently resolved to `addr`, newest first.
    fn domains_at(&self, addr: IpAddr, now: Instant) -> Vec<Domain> {
        let mut out: Vec<Domain> = Vec::new();
        for n in self.names.iter().rev() {
            if n.addr == addr && n.expires > now && !out.contains(&n.domain) {
                out.push(n.domain.clone());
                if out.len() == self.config.max_candidates {
                    break;
                }
            }
        }
        out
    }

    /// Addresses `domain` recently resolved to, newest first.
    fn addrs_of(&self, domain: &Domain, now: Instant) -> Vec<IpAddr> {
        self.names
            .iter()
            .rev()
            .filter(|n| &n.domain == domain && n.expires > now)
            .map(|n| n.addr)
            .collect()
    }
}

fn report(result: io::Result<()>) {
    if let Err(e) = result {
        crate::log!("table update failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{Strategy, Verdict};

    #[derive(Default)]
    struct FakeTable {
        addrs: Vec<IpAddr>,
    }

    impl Table for FakeTable {
        fn add(&mut self, addrs: &[IpAddr]) -> io::Result<()> {
            for a in addrs {
                assert!(!self.addrs.contains(a), "{a} added twice");
                self.addrs.push(*a);
            }
            Ok(())
        }

        fn remove(&mut self, addrs: &[IpAddr]) -> io::Result<()> {
            self.addrs.retain(|a| !addrs.contains(a));
            Ok(())
        }
    }

    fn d(name: &str) -> Domain {
        Domain::parse(name).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn answer(name: &str, addrs: &[&str], ttl: u32) -> Answer {
        Answer {
            domain: Some(d(name)),
            rcode: 0,
            addrs: addrs.iter().map(|a| ip(a)).collect(),
            ttl: Some(ttl),
        }
    }

    fn engine() -> Engine<FakeTable> {
        Engine::new(FakeTable::default(), Config::default())
    }

    fn blocked(name: &str) -> Outcome {
        Outcome {
            domain: d(name),
            verdict: Verdict::Blocked(Some(Strategy::TlsRecordSplit)),
        }
    }

    #[test]
    fn named_reset_probes_and_a_block_fills_the_table_from_known_answers() {
        let t0 = Instant::now();
        let mut e = engine();
        e.answer(
            &answer("womenhelp.org", &["199.58.81.252", "199.58.81.253"], 300),
            t0,
        );
        let probes = e.signal(
            Signal::TlsReset {
                server: ip("199.58.81.252"),
                sni: Some(d("womenhelp.org")),
            },
            t0,
        );
        assert_eq!(
            probes,
            [Probe {
                domain: d("womenhelp.org"),
                addr: Some(ip("199.58.81.252"))
            }]
        );
        assert!(e.table.addrs.is_empty(), "no bypass before the probe");
        e.outcome(blocked("womenhelp.org"), t0);
        assert_eq!(e.table.addrs.len(), 2);
    }

    #[test]
    fn answers_for_a_bypassed_domain_enter_the_table_immediately() {
        let t0 = Instant::now();
        let mut e = engine();
        e.signal(
            Signal::TlsReset {
                server: ip("199.58.81.252"),
                sni: Some(d("womenhelp.org")),
            },
            t0,
        );
        e.outcome(blocked("womenhelp.org"), t0);
        e.answer(&answer("womenhelp.org", &["203.0.113.7"], 60), t0);
        assert_eq!(e.table.addrs, [ip("203.0.113.7")]);
        e.answer(&answer("example.com", &["203.0.113.8"], 60), t0);
        assert_eq!(e.table.addrs, [ip("203.0.113.7")]);
    }

    #[test]
    fn unnamed_reset_probes_recent_domains_at_that_address() {
        let t0 = Instant::now();
        let mut e = engine();
        e.answer(&answer("a.example", &["203.0.113.1"], 60), t0);
        e.answer(&answer("b.example", &["203.0.113.1"], 60), t0);
        e.answer(&answer("c.example", &["203.0.113.2"], 60), t0);
        let probes = e.signal(
            Signal::TlsReset {
                server: ip("203.0.113.1"),
                sni: None,
            },
            t0,
        );
        let domains: Vec<_> = probes.into_iter().map(|p| p.domain).collect();
        assert_eq!(domains, [d("b.example"), d("a.example")]);
    }

    #[test]
    fn table_entries_expire_after_ttl_plus_grace_and_lift_removes_them() {
        let t0 = Instant::now();
        let mut e = engine();
        e.signal(
            Signal::HttpBlock {
                server: ip("199.58.81.252"),
                host: Some(d("womenhelp.org")),
            },
            t0,
        );
        e.outcome(blocked("womenhelp.org"), t0);
        e.answer(&answer("womenhelp.org", &["203.0.113.7"], 60), t0);
        let expiry = t0 + Duration::from_secs(60 + 600);
        assert_eq!(e.next_wakeup(), Some(expiry));
        e.tick(expiry);
        assert!(e.table.addrs.is_empty());

        e.answer(&answer("womenhelp.org", &["203.0.113.7"], 60), t0);
        e.outcome(
            Outcome {
                domain: d("womenhelp.org"),
                verdict: Verdict::NotBlocked,
            },
            t0,
        );
        assert_eq!(e.table.addrs, [ip("203.0.113.7")], "outcome nobody awaited");
        let reverify = e.tick(t0 + Duration::from_secs(3600));
        assert_eq!(reverify.len(), 1);
        e.outcome(
            Outcome {
                domain: d("womenhelp.org"),
                verdict: Verdict::NotBlocked,
            },
            t0 + Duration::from_secs(3600),
        );
        assert!(e.table.addrs.is_empty());
    }

    #[test]
    fn reset_on_an_unlisted_address_of_a_bypassed_domain_adds_it() {
        let t0 = Instant::now();
        let mut e = engine();
        e.signal(
            Signal::TlsReset {
                server: ip("199.58.81.252"),
                sni: Some(d("womenhelp.org")),
            },
            t0,
        );
        e.outcome(blocked("womenhelp.org"), t0);
        let probes = e.signal(
            Signal::TlsReset {
                server: ip("198.51.100.9"),
                sni: Some(d("womenhelp.org")),
            },
            t0,
        );
        assert!(probes.is_empty());
        assert_eq!(e.table.addrs, [ip("198.51.100.9")]);
    }

    #[test]
    fn name_memory_is_bounded() {
        let t0 = Instant::now();
        let mut e = Engine::new(
            FakeTable::default(),
            Config {
                max_names: 2,
                ..Config::default()
            },
        );
        for i in 0..5 {
            e.answer(&answer(&format!("d{i}.example"), &["203.0.113.1"], 60), t0);
        }
        assert_eq!(e.names.len(), 2);
    }
}
