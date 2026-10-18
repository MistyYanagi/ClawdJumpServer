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

/// The IPv4 address behind an IPv4-mapped (`::ffff:a.b.c.d`), SIIT
/// (`::ffff:0:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`) IPv6 address, so
/// rules and checks see one form of each address.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let s = v6.segments();
            let embedded =
                std::net::Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
            // ::ffff:0:a.b.c.d (SIIT)
            if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
                return IpAddr::V4(embedded);
            }
            // ::a.b.c.d (deprecated IPv4-compatible), but not :: or ::1.
            if s[..6] == [0; 6] && (s[6] != 0 || s[7] > 1) {
                return IpAddr::V4(embedded);
            }
            ip
        }
    }
}

/// Parses the legacy numeric IPv4 forms that resolvers (`inet_aton`)
/// accept: `2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`, `169.254.43518`.
/// Returns `None` for ordinary dotted quads (handled by the std parser) and
/// for names.
pub fn parse_legacy_v4(h: &str) -> Option<std::net::Ipv4Addr> {
    if h.is_empty() || h.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for p in &parts {
        let n = if let Some(x) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if x.is_empty() {
                0
            } else {
                u64::from_str_radix(x, 16).ok()?
            }
        } else if p.len() > 1 && p.starts_with('0') {
            u64::from_str_radix(&p[1..], 8).ok()?
        } else {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u64>().ok()?
        };
        nums.push(n);
    }
    let (head, last) = nums.split_at(nums.len() - 1);
    if head.iter().any(|&n| n > 255) {
        return None;
    }
    let rest_bits = 8 * (4 - head.len() as u32);
    if last[0] >= 1u64 << rest_bits {
        return None;
    }
    let mut v: u64 = 0;
    for (i, &n) in head.iter().enumerate() {
        v |= n << (24 - 8 * i as u32);
    }
    v |= last[0];
    Some(std::net::Ipv4Addr::from(v as u32))
}

/// An IP literal in any accepted spelling, canonicalized.
pub fn host_ip(host: &str) -> Option<IpAddr> {
    let h = host.trim_end_matches('.');
    let h = h.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    parse_legacy_v4(h).map(IpAddr::V4)
}

fn canonical_net(n: IpNet) -> IpNet {
    match n {
        IpNet::V6(v6) if v6.prefix_len() >= 96 => match canonical(IpAddr::V6(v6.network())) {
            IpAddr::V4(a) => IpNet::new(IpAddr::V4(a), v6.prefix_len() - 96).unwrap_or(n),
            IpAddr::V6(_) => n,
        },
        _ => n,
    }
}

fn parse_pat(h: &str) -> Result<HostPat, String> {
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    if h == "*" {
        return Ok(HostPat::Any);
    }
    if let Ok(n) = h.parse::<IpNet>() {
        return Ok(HostPat::Net(canonical_net(n.trunc())));
    }
    if let Some(ip) = host_ip(&h) {
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
        // IP literals in any spelling are matched as addresses only.
        let ip = host_ip(host);
        match parse_pat(&self.host) {
            Ok(HostPat::Any) => true,
            Ok(HostPat::Exact(e)) => ip.is_none() && host == e,
            Ok(HostPat::Suffix(s)) => ip.is_none() && host.ends_with(&format!(".{s}")),
            Ok(HostPat::Net(n)) => ip.map(|ip| n.contains(&ip)).unwrap_or(false),
            Err(_) => false,
        }
    }

    /// Does this rule name `ip` explicitly by IP/CIDR?
    fn names_ip(&self, ip: &IpAddr, port: u16) -> bool {
        let ip = canonical(*ip);
        self.port_ok(port) && matches!(parse_pat(&self.host), Ok(HostPat::Net(n)) if n.contains(&ip))
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
/// unique-local, multicast, unspecified, documentation, benchmarking, IETF
/// protocol assignments, and transition prefixes that embed such an IPv4
/// address (mapped, compatible, SIIT, NAT64, 6to4) or tunnel to an
/// arbitrary one (Teredo).
pub fn is_sensitive(ip: &IpAddr) -> bool {
    match canonical(*ip) {
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
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24 IETF (incl. .170/.171)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 6to4 relay anycast
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if s[0] == 0x2002 {
                // 6to4: the next 32 bits are an IPv4 address.
                let v4 =
                    std::net::Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
                return is_sensitive(&IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || s[..6] == [0; 6] // remaining ::/96 (compatible forms are canonicalized above)
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 (old site-local)
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x2001 && s[1] == 0) // Teredo 2001::/32
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64 may map to private v4
                || (s[0] == 0x100 && s[1..4] == [0, 0, 0]) // 100::/64 discard
        }
    }
}

/// Final check on a resolved address (SSRF guard). Deny rules naming the
/// IP win; sensitive addresses require an allow rule that names them by
/// IP or CIDR (a `*` or domain rule is not enough).
pub fn ip_allowed(rules: &[NetRule], ip: &IpAddr, port: u16) -> bool {
    let ip = &canonical(*ip);
    if rules.iter().any(|r| !r.allow && r.names_ip(ip, port)) {
        return false;
    }
    if is_sensitive(ip) {
        return rules.iter().any(|r| r.allow && r.names_ip(ip, port));
    }
    true
}

/// Cloud metadata and other link-local endpoints. Local forwards may reach
/// private and loopback services by name (that is their purpose), but these
/// only when a rule names them by IP or CIDR.
pub fn is_metadata(ip: &IpAddr) -> bool {
    match canonical(*ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_link_local() // 169.254/16: AWS, GCP, Azure, OpenStack, ...
                || o == [100, 100, 100, 200] // Alibaba Cloud
                || o == [192, 0, 0, 192] // Oracle Cloud
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xffc0) == 0xfe80 || s == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]
        }
    }
}

/// Post-DNS check for local forwards (`forward_targets`): deny rules naming
/// the IP win, metadata endpoints need a rule naming them by IP, anything
/// else matched by name is allowed.
pub fn forward_ip_allowed(rules: &[NetRule], ip: &IpAddr, port: u16) -> bool {
    let ip = &canonical(*ip);
    if rules.iter().any(|r| !r.allow && r.names_ip(ip, port)) {
        return false;
    }
    if is_metadata(ip) {
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
    fn alternate_spellings_hit_ip_rules() {
        let rules = vec![
            NetRule::allow("*", &[]),
            NetRule {
                allow: false,
                host: "169.254.0.0/16".into(),
                ports: vec![],
            },
            NetRule {
                allow: false,
                host: "8.8.8.0/24".into(),
                ports: vec![],
            },
        ];
        for h in [
            "2852039166",
            "0xa9fea9fe",
            "0251.0376.0251.0376",
            "169.254.43518",
            "::ffff:169.254.169.254",
            "[::ffff:a9fe:a9fe]",
            "::ffff:8.8.8.8",
            "::8.8.8.8",
        ] {
            assert!(!name_allowed(&rules, h, 80), "{h} must hit a deny rule");
        }
        assert_eq!(parse_legacy_v4("127.1"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(parse_legacy_v4("0x7f.1"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(parse_legacy_v4("2130706433"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(parse_legacy_v4("1.2.3.4"), None);
        assert_eq!(parse_legacy_v4("example"), None);
        assert_eq!(parse_legacy_v4("1.256.3"), None);
        // A mapped address is checked as the IPv4 it is.
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!ip_allowed(&rules, &ip, 53));
        // Exact name rules never match IP literals.
        let named = vec![NetRule::allow("2130706433", &[])];
        assert!(ip_allowed(&named, &"127.0.0.1".parse().unwrap(), 80));
    }

    #[test]
    fn more_sensitive_ranges() {
        let any = vec![NetRule::allow("*", &[])];
        for ip in [
            "192.0.0.170",
            "192.88.99.1",
            "::7f00:1",
            "::a9fe:a9fe",
            "::ffff:0:7f00:1",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::",
            "2001:0:4136:e378::1",
            "fec0::1",
            "100::1",
            "64:ff9b::a9fe:a9fe",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!ip_allowed(&any, &ip, 80), "{ip} must be blocked by default");
        }
        assert!(ip_allowed(&any, &"2002:808:808::1".parse().unwrap(), 80));
        assert!(ip_allowed(&any, &"2606:4700::1111".parse().unwrap(), 443));
    }

    #[test]
    fn forward_post_dns() {
        let rules = vec![
            NetRule::allow("*", &[]),
            NetRule {
                allow: false,
                host: "10.9.0.0/16".into(),
                ports: vec![],
            },
        ];
        assert!(forward_ip_allowed(&rules, &"10.1.2.3".parse().unwrap(), 80));
        assert!(forward_ip_allowed(&rules, &"127.0.0.1".parse().unwrap(), 80));
        assert!(!forward_ip_allowed(&rules, &"10.9.1.1".parse().unwrap(), 80));
        assert!(!forward_ip_allowed(
            &rules,
            &"::ffff:10.9.1.1".parse().unwrap(),
            80
        ));
        for m in ["169.254.169.254", "fd00:ec2::254", "100.100.100.200", "fe80::1"] {
            assert!(!forward_ip_allowed(&rules, &m.parse().unwrap(), 80), "{m}");
        }
        let named = vec![NetRule::allow("169.254.169.254", &["80"])];
        assert!(forward_ip_allowed(
            &named,
            &"169.254.169.254".parse().unwrap(),
            80
        ));
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
