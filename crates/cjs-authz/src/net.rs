//! Host and port rules, and the SSRF guard.
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn contains(&self, p: u16) -> bool {
        self.lo <= p && p <= self.hi
    }
}

impl std::str::FromStr for PortRange {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s == "*" {
            return Ok(PortRange { lo: 1, hi: 65535 });
        }
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let lo: u16 = a.trim().parse().map_err(|_| format!("bad port {s:?}"))?;
        let hi: u16 = b.trim().parse().map_err(|_| format!("bad port {s:?}"))?;
        if lo == 0 || lo > hi {
            return Err(format!("bad port range {s:?}"));
        }
        Ok(PortRange { lo, hi })
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u16),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => format!("{n}").parse().map_err(serde::de::Error::custom),
            Raw::S(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// `host` is one of: `*` (any name or public IP), `example.com` (exact),
/// `*.example.com` (subdomains only), an IP, or a CIDR. Matching is case
/// insensitive. `ports` empty means any port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetRule {
    #[serde(default = "allow_default")]
    pub allow: bool,
    pub host: String,
    #[serde(default)]
    pub ports: Vec<PortRange>,
}

fn allow_default() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPat {
    Any,
    Exact(String),
    Suffix(String),
    Net(IpNet),
}

fn parse_pat(h: &str) -> Result<HostPat, String> {
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    if h == "*" {
        return Ok(HostPat::Any);
    }
    if let Ok(n) = h.parse::<IpNet>() {
        return Ok(HostPat::Net(n.trunc()));
    }
    if let Ok(ip) = h.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        return Ok(HostPat::Net(IpNet::from(ip)));
    }
    if let Some(rest) = h.strip_prefix("*.") {
        if rest.is_empty() || rest.contains('*') {
            return Err(format!("bad host pattern {h:?}"));
        }
        return Ok(HostPat::Suffix(rest.to_string()));
    }
    if h.is_empty() || h.contains('*') || h.contains('/') {
        return Err(format!("bad host pattern {h:?}"));
    }
    Ok(HostPat::Exact(h))
}

impl NetRule {
    pub fn allow(host: &str, ports: &[&str]) -> Self {
        Self {
            allow: true,
            host: host.into(),
            ports: ports.iter().map(|p| p.parse().expect("valid port")).collect(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        parse_pat(&self.host).map(|_| ())
    }

    fn port_ok(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.iter().any(|r| r.contains(port))
    }

    /// Does this rule match the requested name (before DNS)?
    pub fn matches_name(&self, host: &str, port: u16) -> bool {
        if !self.port_ok(port) {
            return false;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let host = host.trim_matches(|c| c == '[' || c == ']');
        match parse_pat(&self.host) {
            Ok(HostPat::Any) => true,
            Ok(HostPat::Exact(e)) => host == e,
            Ok(HostPat::Suffix(s)) => host.ends_with(&format!(".{s}")),
            Ok(HostPat::Net(n)) => host.parse::<IpAddr>().map(|ip| n.contains(&ip)).unwrap_or(false),
            Err(_) => false,
        }
    }

    /// Does this rule name `ip` explicitly by IP/CIDR?
    fn names_ip(&self, ip: &IpAddr, port: u16) -> bool {
        self.port_ok(port) && matches!(parse_pat(&self.host), Ok(HostPat::Net(n)) if n.contains(ip))
    }
}

/// Is a requested `host:port` allowed by name? Deny rules win.
pub fn name_allowed(rules: &[NetRule], host: &str, port: u16) -> bool {
    if rules.iter().any(|r| !r.allow && r.matches_name(host, port)) {
        return false;
    }
    rules.iter().any(|r| r.allow && r.matches_name(host, port))
}

/// Addresses that must never be reached unless a rule names them by IP:
/// loopback, private ranges, link-local (incl. cloud metadata), CGNAT,
/// unique-local, multicast, unspecified, documentation and benchmarking.
pub fn is_sensitive(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_sensitive(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64 may map to private v4
        }
    }
}

/// Final check on a resolved address (SSRF guard). Deny rules naming the
/// IP win; sensitive addresses require an allow rule that names them by
/// IP or CIDR (a `*` or domain rule is not enough).
pub fn ip_allowed(rules: &[NetRule], ip: &IpAddr, port: u16) -> bool {
    if rules.iter().any(|r| !r.allow && r.names_ip(ip, port)) {
        return false;
    }
    if is_sensitive(ip) {
        return rules.iter().any(|r| r.allow && r.names_ip(ip, port));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matching() {
        let rules = vec![
            NetRule::allow("*.github.com", &["443"]),
            NetRule::allow("crates.io", &[]),
            NetRule {
                allow: false,
                host: "evil.github.com".into(),
                ports: vec![],
            },
        ];
        assert!(name_allowed(&rules, "api.github.com", 443));
        assert!(!name_allowed(&rules, "github.com", 443));
        assert!(!name_allowed(&rules, "api.github.com", 80));
        assert!(name_allowed(&rules, "CRATES.IO.", 80));
        assert!(!name_allowed(&rules, "evil.github.com", 443));
        assert!(!name_allowed(&rules, "example.com", 443));
    }

    #[test]
    fn ssrf_guard() {
        let any = vec![NetRule::allow("*", &[])];
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "100.64.0.1",
            "0.0.0.0",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!ip_allowed(&any, &ip, 80), "{ip} must be blocked by default");
        }
        assert!(ip_allowed(&any, &"1.1.1.1".parse().unwrap(), 443));
        let explicit = vec![NetRule::allow("127.0.0.1/32", &["8080"])];
        assert!(ip_allowed(&explicit, &"127.0.0.1".parse().unwrap(), 8080));
        assert!(!ip_allowed(&explicit, &"127.0.0.1".parse().unwrap(), 22));
        assert!(!ip_allowed(&explicit, &"169.254.169.254".parse().unwrap(), 8080));
    }

    #[test]
    fn port_ranges_parse() {
        let r: PortRange = "8000-8100".parse().unwrap();
        assert!(r.contains(8050) && !r.contains(80));
        assert!("0".parse::<PortRange>().is_err());
        assert!("9-1".parse::<PortRange>().is_err());
        let rule: NetRule = serde_json::from_str(r#"{"host":"*.x.com","ports":[443,"8000-8100"]}"#).unwrap();
        assert!(rule.allow && rule.ports.len() == 2);
    }
}
