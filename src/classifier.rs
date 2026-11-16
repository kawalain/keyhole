//! Decides which domains need a bypass, from passive evidence and active
//! probe outcomes (ADR 0008).
//!
//! The classifier is pure: it never touches the network, the clock or the
//! operating system. Callers feed it [`Evidence`] and [`Outcome`]s with the
//! current time, carry out the returned [`Action`]s, and call
//! [`Classifier::tick`] at [`Classifier::next_wakeup`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::domain::Domain;

/// A way around a block (ADR 0003).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Strategy {
    /// Split the ClientHello into two TLS records inside the SNI.
    TlsRecordSplit,
}

/// Something observed passively that suggests a block. Evidence only ever
/// leads to a probe, never directly to a bypass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// A reset followed a ClientHello carrying this SNI.
    SniReset { domain: Domain, addr: IpAddr },
    /// A plain-HTTP response redirected to the block page.
    HttpBlockRedirect { domain: Domain, addr: IpAddr },
}

/// What a probe concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The domain works without a bypass.
    NotBlocked,
    /// The control probe worked and the real one did not. Carries the first
    /// strategy that got through, or `None` when none did.
    Blocked(Option<Strategy>),
    /// The control probe failed too, so nothing can be concluded.
    Inconclusive,
}

/// The result of a probe requested by [`Action::Probe`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub domain: Domain,
    pub verdict: Verdict,
}

/// Work the caller must carry out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Probe `domain` and report back with [`Classifier::record`].
    /// `addr` is the address the evidence was seen on; `None` means the
    /// prober resolves the domain itself.
    Probe {
        domain: Domain,
        addr: Option<IpAddr>,
    },
    /// Start bypassing `domain` with `strategy`.
    Apply { domain: Domain, strategy: Strategy },
    /// Stop bypassing `domain` with `strategy`.
    Lift { domain: Domain, strategy: Strategy },
}

/// Timings and limits. The defaults suit a home router.
#[derive(Clone, Debug)]
pub struct Config {
    /// A probe without an outcome after this long counts as inconclusive.
    pub probe_timeout: Duration,
    /// After a `NotBlocked` verdict, evidence is ignored for this long.
    pub clear_cooldown: Duration,
    /// After an inconclusive probe, wait this long before probing again.
    pub inconclusive_retry: Duration,
    /// First re-verification interval of a blocked domain; it doubles on
    /// every confirmation up to `verify_max`.
    pub verify_initial: Duration,
    pub verify_max: Duration,
    /// Upper bound on tracked domains; evidence for new domains beyond it
    /// is dropped.
    pub max_entries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_secs(30),
            clear_cooldown: Duration::from_secs(6 * 3600),
            inconclusive_retry: Duration::from_secs(10 * 60),
            verify_initial: Duration::from_secs(3600),
            verify_max: Duration::from_secs(7 * 24 * 3600),
            max_entries: 4096,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    /// A probe is outstanding.
    Probing { deadline: Instant },
    /// Blocked entries are re-probed at `until`; other entries are forgotten.
    Waiting { until: Instant },
}

impl Phase {
    fn at(self) -> Instant {
        match self {
            Phase::Probing { deadline } => deadline,
            Phase::Waiting { until } => until,
        }
    }
}

#[derive(Debug)]
struct Entry {
    blocked: bool,
    strategy: Option<Strategy>,
    interval: Duration,
    phase: Phase,
}

pub struct Classifier {
    config: Config,
    entries: HashMap<Domain, Entry>,
}

impl Classifier {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            entries: HashMap::new(),
        }
    }

    /// Feeds passive evidence. Evidence for a domain that is already being
    /// probed, known to be blocked, or recently cleared is ignored.
    ///
    /// A reset on a domain that is already bypassed usually means the client
    /// reached an address the bypass does not cover yet (for example through
    /// its own DoH); the caller handles that with [`Classifier::strategy`].
    pub fn observe(&mut self, evidence: Evidence, now: Instant) -> Vec<Action> {
        let (Evidence::SniReset { domain, addr } | Evidence::HttpBlockRedirect { domain, addr }) =
            evidence;
        if self.entries.contains_key(&domain) || self.entries.len() >= self.config.max_entries {
            return Vec::new();
        }
        self.entries.insert(
            domain.clone(),
            Entry {
                blocked: false,
                strategy: None,
                interval: self.config.verify_initial,
                phase: Phase::Probing {
                    deadline: now + self.config.probe_timeout,
                },
            },
        );
        vec![Action::Probe {
            domain,
            addr: Some(addr),
        }]
    }

    /// Feeds the outcome of a requested probe. Outcomes nobody is waiting
    /// for (late, duplicated) are ignored.
    pub fn record(&mut self, outcome: Outcome, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some(entry) = self.entries.get_mut(&outcome.domain)
            && matches!(entry.phase, Phase::Probing { .. })
        {
            Self::settle(
                &self.config,
                &outcome.domain,
                entry,
                outcome.verdict,
                now,
                &mut actions,
            );
        }
        actions
    }

    /// Advances time: times out probes and starts due re-verifications.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        let config = &self.config;
        self.entries.retain(|domain, entry| {
            if entry.phase.at() > now {
                return true;
            }
            match entry.phase {
                Phase::Probing { .. } => {
                    Self::settle(
                        config,
                        domain,
                        entry,
                        Verdict::Inconclusive,
                        now,
                        &mut actions,
                    );
                    true
                }
                Phase::Waiting { .. } if entry.blocked => {
                    entry.phase = Phase::Probing {
                        deadline: now + config.probe_timeout,
                    };
                    actions.push(Action::Probe {
                        domain: domain.clone(),
                        addr: None,
                    });
                    true
                }
                Phase::Waiting { .. } => false,
            }
        });
        actions
    }

    /// When [`Classifier::tick`] next has work to do; `None` when idle.
    pub fn next_wakeup(&self) -> Option<Instant> {
        self.entries.values().map(|e| e.phase.at()).min()
    }

    /// The bypass currently applied to `domain`.
    pub fn strategy(&self, domain: &Domain) -> Option<Strategy> {
        self.entries.get(domain).and_then(|e| e.strategy)
    }

    fn settle(
        config: &Config,
        domain: &Domain,
        entry: &mut Entry,
        verdict: Verdict,
        now: Instant,
        actions: &mut Vec<Action>,
    ) {
        let (blocked, strategy, wait) = match verdict {
            Verdict::NotBlocked => (false, None, config.clear_cooldown),
            Verdict::Inconclusive => (entry.blocked, entry.strategy, config.inconclusive_retry),
            Verdict::Blocked(strategy) => {
                entry.interval = if entry.blocked {
                    (entry.interval * 2).min(config.verify_max)
                } else {
                    config.verify_initial
                };
                (true, strategy, entry.interval)
            }
        };
        if entry.strategy != strategy {
            if let Some(old) = entry.strategy {
                actions.push(Action::Lift {
                    domain: domain.clone(),
                    strategy: old,
                });
            }
            if let Some(new) = strategy {
                actions.push(Action::Apply {
                    domain: domain.clone(),
                    strategy: new,
                });
            }
        }
        entry.blocked = blocked;
        entry.strategy = strategy;
        entry.phase = Phase::Waiting { until: now + wait };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(199, 58, 81, 252));

    fn cfg() -> Config {
        Config {
            probe_timeout: secs(30),
            clear_cooldown: secs(600),
            inconclusive_retry: secs(60),
            verify_initial: secs(1000),
            verify_max: secs(3000),
            max_entries: 8,
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn d(name: &str) -> Domain {
        Domain::parse(name).unwrap()
    }

    fn reset(name: &str) -> Evidence {
        Evidence::SniReset {
            domain: d(name),
            addr: ADDR,
        }
    }

    fn probe(name: &str, addr: Option<IpAddr>) -> Action {
        Action::Probe {
            domain: d(name),
            addr,
        }
    }

    fn outcome(name: &str, verdict: Verdict) -> Outcome {
        Outcome {
            domain: d(name),
            verdict,
        }
    }

    const SPLIT: Verdict = Verdict::Blocked(Some(Strategy::TlsRecordSplit));

    /// A classifier where `womenhelp.org` was confirmed blocked at `t0`.
    fn bypassed(t0: Instant) -> Classifier {
        let mut c = Classifier::new(cfg());
        c.observe(reset("womenhelp.org"), t0);
        c.record(outcome("womenhelp.org", SPLIT), t0);
        c
    }

    #[test]
    fn evidence_on_unknown_domain_requests_one_probe_on_the_seen_address() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        assert_eq!(
            c.observe(reset("womenhelp.org"), t0),
            [probe("womenhelp.org", Some(ADDR))]
        );
        assert_eq!(c.observe(reset("womenhelp.org"), t0 + secs(1)), []);
        assert_eq!(c.strategy(&d("womenhelp.org")), None);
    }

    #[test]
    fn http_redirect_is_evidence_like_a_reset() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        let http = Evidence::HttpBlockRedirect {
            domain: d("womenhelp.org"),
            addr: ADDR,
        };
        assert_eq!(c.observe(http, t0), [probe("womenhelp.org", Some(ADDR))]);
        assert_eq!(c.observe(reset("womenhelp.org"), t0), []);
    }

    #[test]
    fn blocked_verdict_with_a_strategy_applies_the_bypass() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        c.observe(reset("womenhelp.org"), t0);
        assert_eq!(
            c.record(outcome("womenhelp.org", SPLIT), t0),
            [Action::Apply {
                domain: d("womenhelp.org"),
                strategy: Strategy::TlsRecordSplit,
            }]
        );
        assert_eq!(
            c.strategy(&d("womenhelp.org")),
            Some(Strategy::TlsRecordSplit)
        );
    }

    #[test]
    fn blocked_without_a_working_strategy_applies_nothing_but_is_reverified() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        c.observe(reset("womenhelp.org"), t0);
        assert_eq!(
            c.record(outcome("womenhelp.org", Verdict::Blocked(None)), t0),
            []
        );
        assert_eq!(c.observe(reset("womenhelp.org"), t0 + secs(5)), []);
        assert_eq!(c.next_wakeup(), Some(t0 + secs(1000)));
        assert_eq!(c.tick(t0 + secs(1000)), [probe("womenhelp.org", None)]);
    }

    #[test]
    fn not_blocked_suppresses_evidence_for_the_cooldown_then_forgets() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        c.observe(reset("example.com"), t0);
        assert_eq!(
            c.record(outcome("example.com", Verdict::NotBlocked), t0),
            []
        );
        assert_eq!(c.observe(reset("example.com"), t0 + secs(599)), []);
        assert_eq!(c.tick(t0 + secs(600)), []);
        assert_eq!(c.next_wakeup(), None);
        assert_eq!(
            c.observe(reset("example.com"), t0 + secs(601)),
            [probe("example.com", Some(ADDR))]
        );
    }

    #[test]
    fn bypass_is_reverified_with_doubling_interval_up_to_the_cap() {
        let t0 = Instant::now();
        let mut c = bypassed(t0);
        let mut t = t0;
        for interval in [1000, 2000, 3000, 3000] {
            assert_eq!(c.next_wakeup(), Some(t + secs(interval)));
            t += secs(interval);
            assert_eq!(c.tick(t), [probe("womenhelp.org", None)]);
            assert_eq!(
                c.strategy(&d("womenhelp.org")),
                Some(Strategy::TlsRecordSplit),
                "the bypass stays on while it is re-verified"
            );
            assert_eq!(c.record(outcome("womenhelp.org", SPLIT), t), []);
        }
    }

    #[test]
    fn reverification_that_finds_no_block_lifts_the_bypass() {
        let t0 = Instant::now();
        let mut c = bypassed(t0);
        let t = t0 + secs(1000);
        c.tick(t);
        assert_eq!(
            c.record(outcome("womenhelp.org", Verdict::NotBlocked), t),
            [Action::Lift {
                domain: d("womenhelp.org"),
                strategy: Strategy::TlsRecordSplit,
            }]
        );
        assert_eq!(c.strategy(&d("womenhelp.org")), None);
    }

    #[test]
    fn inconclusive_reverification_keeps_the_bypass_and_retries_soon() {
        let t0 = Instant::now();
        let mut c = bypassed(t0);
        let t = t0 + secs(1000);
        c.tick(t);
        assert_eq!(
            c.record(outcome("womenhelp.org", Verdict::Inconclusive), t),
            []
        );
        assert_eq!(
            c.strategy(&d("womenhelp.org")),
            Some(Strategy::TlsRecordSplit)
        );
        assert_eq!(c.next_wakeup(), Some(t + secs(60)));
    }

    #[test]
    fn probe_without_an_outcome_times_out_as_inconclusive() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        c.observe(reset("womenhelp.org"), t0);
        assert_eq!(c.next_wakeup(), Some(t0 + secs(30)));
        assert_eq!(c.tick(t0 + secs(30)), []);
        assert_eq!(c.observe(reset("womenhelp.org"), t0 + secs(89)), []);
        assert_eq!(c.tick(t0 + secs(90)), []);
        assert_eq!(
            c.observe(reset("womenhelp.org"), t0 + secs(91)),
            [probe("womenhelp.org", Some(ADDR))]
        );
    }

    #[test]
    fn outcomes_nobody_waits_for_are_ignored() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        assert_eq!(c.record(outcome("womenhelp.org", SPLIT), t0), []);
        assert_eq!(c.strategy(&d("womenhelp.org")), None);

        let mut c = bypassed(t0);
        assert_eq!(
            c.record(outcome("womenhelp.org", Verdict::NotBlocked), t0),
            [],
            "a duplicate outcome must not lift a fresh verdict"
        );
    }

    #[test]
    fn evidence_for_new_pairs_beyond_capacity_is_dropped() {
        let t0 = Instant::now();
        let mut c = Classifier::new(cfg());
        for i in 0..8 {
            assert_eq!(c.observe(reset(&format!("d{i}.example")), t0).len(), 1);
        }
        assert_eq!(c.observe(reset("womenhelp.org"), t0), []);
    }

    #[test]
    fn idle_classifier_needs_no_wakeup() {
        assert_eq!(Classifier::new(cfg()).next_wakeup(), None);
    }
}
