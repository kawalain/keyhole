//! Normalised domain names, as they appear in SNI, HTTP `Host` and DNS.

use std::fmt;

/// A lower-case, fully qualified host name without a trailing dot.
///
/// Only names that can be censored by name are accepted: at least two labels,
/// LDH characters (plus `_`, which some DNS names use), and not an IP literal.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(Box<str>);

impl Domain {
    /// Parses and normalises `name`; returns `None` when it is not a usable
    /// host name.
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.is_empty() || name.len() > 253 {
            return None;
        }
        let name = name.to_ascii_lowercase();
        let mut labels = 0;
        let mut last = "";
        for label in name.split('.') {
            let valid = (1..=63).contains(&label.len())
                && label.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                })
                && !label.starts_with('-')
                && !label.ends_with('-');
            if !valid {
                return None;
            }
            labels += 1;
            last = label;
        }
        let ip_literal = last.bytes().all(|b| b.is_ascii_digit());
        (labels >= 2 && !ip_literal).then(|| Self(name.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Domain({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Domain;

    fn parse(s: &str) -> Option<String> {
        Domain::parse(s).map(|d| d.to_string())
    }

    #[test]
    fn normalises_case_and_trailing_dot() {
        assert_eq!(parse("WomenHelp.ORG."), Some("womenhelp.org".into()));
    }

    #[test]
    fn accepts_punycode_digits_hyphens_and_underscores() {
        assert_eq!(parse("xn--3e0b707e.kr"), Some("xn--3e0b707e.kr".into()));
        assert_eq!(
            parse("a-1._dmarc.example.com"),
            Some("a-1._dmarc.example.com".into())
        );
    }

    #[test]
    fn rejects_single_labels_and_ip_literals() {
        assert_eq!(parse("localhost"), None);
        assert_eq!(parse("199.58.81.252"), None);
    }

    #[test]
    fn rejects_malformed_names() {
        for bad in [
            "",
            ".",
            "a..b",
            "-a.com",
            "a-.com",
            "a b.com",
            "한국.kr",
            "a.com..",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
        assert_eq!(parse(&format!("{}.com", "a".repeat(64))), None);
        assert_eq!(parse(&format!("{}com", "a.".repeat(127))), None);
    }
}
