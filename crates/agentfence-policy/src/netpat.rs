//! Network patterns (policy-model §2.4): host patterns and address patterns.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix_len == 0 { 0 } else { u32::MAX << (32 - self.prefix_len as u32) };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix_len == 0 { 0 } else { u128::MAX << (128 - self.prefix_len as u32) };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
    fn parse(s: &str) -> Option<IpNet> {
        let (a, len) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr = normalize(a.parse::<IpAddr>().ok()?);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix_len = len.unwrap_or(max);
        (prefix_len <= max).then_some(IpNet { addr, prefix_len })
    }
}

/// IPv4-mapped IPv6 addresses are treated as their IPv4 form.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetPattern {
    /// Exact host, or `*.domain` (any subdomain, not the apex).
    Host { host: String, wildcard: bool, port: Option<u16> },
    Addr { nets: Vec<IpNet>, port: Option<u16> },
}

pub fn normalize_host(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

fn split_port(s: &str) -> Result<(&str, Option<u16>), String> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, after) = rest.split_once(']').ok_or("unterminated [")?;
        return match after.strip_prefix(':') {
            Some(p) => Ok((addr, Some(p.parse().map_err(|_| format!("bad port {p:?}"))?))),
            None if after.is_empty() => Ok((addr, None)),
            None => Err(format!("unexpected {after:?}")),
        };
    }
    match s.rsplit_once(':') {
        // A bare IPv6 literal has several colons; only `x:port` with a single colon has a port.
        Some((h, p)) if !h.contains(':') => Ok((h, Some(p.parse().map_err(|_| format!("bad port {p:?}"))?))),
        _ => Ok((s, None)),
    }
}

impl NetPattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (hostpart, port) = split_port(s)?;
        if hostpart.eq_ignore_ascii_case("localhost") {
            let nets = vec![
                IpNet { addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), prefix_len: 8 },
                IpNet { addr: IpAddr::V6(Ipv6Addr::LOCALHOST), prefix_len: 128 },
            ];
            return Ok(NetPattern::Addr { nets, port });
        }
        if let Some(net) = IpNet::parse(hostpart) {
            return Ok(NetPattern::Addr { nets: vec![net], port });
        }
        if hostpart.contains('/') {
            return Err(format!("invalid CIDR {hostpart:?}"));
        }
        let (wildcard, host) = match hostpart.strip_prefix("*.") {
            Some(h) => (true, h),
            None => (false, hostpart),
        };
        let host = normalize_host(host);
        let valid = !host.is_empty()
            && host.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        if !valid {
            return Err(format!("invalid host {hostpart:?}"));
        }
        Ok(NetPattern::Host { host, wildcard, port })
    }

    fn port_ok(want: Option<u16>, port: u16) -> bool {
        want.is_none_or(|p| p == port)
    }

    pub fn matches_host(&self, host: &str, port: u16) -> bool {
        match self {
            NetPattern::Host { host: h, wildcard, port: p } => {
                let host = normalize_host(host);
                let name_ok = if *wildcard {
                    host.len() > h.len() + 1 && host.ends_with(h.as_str()) && host[..host.len() - h.len()].ends_with('.')
                } else {
                    host == *h
                };
                name_ok && Self::port_ok(*p, port)
            }
            NetPattern::Addr { .. } => false,
        }
    }

    pub fn matches_addr(&self, ip: IpAddr, port: u16) -> bool {
        match self {
            NetPattern::Addr { nets, port: p } => nets.iter().any(|n| n.contains(ip)) && Self::port_ok(*p, port),
            NetPattern::Host { .. } => false,
        }
    }

    pub fn is_addr(&self) -> bool {
        matches!(self, NetPattern::Addr { .. })
    }

    /// True when every address this pattern names is loopback (for `network.listen`).
    pub fn is_loopback_only(&self) -> bool {
        match self {
            NetPattern::Addr { nets, .. } => nets.iter().all(|n| match n.addr {
                IpAddr::V4(a) => a.is_loopback() && n.prefix_len >= 8,
                IpAddr::V6(a) => a.is_loopback(),
            }),
            NetPattern::Host { .. } => false,
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            NetPattern::Host { port, .. } | NetPattern::Addr { port, .. } => *port,
        }
    }
}

/// Built-in reserved ranges (policy-model §4.2). Returns the range kind.
pub fn reserved_range(ip: IpAddr) -> Option<&'static str> {
    match normalize(ip) {
        IpAddr::V4(a) => {
            let o = a.octets();
            if a.is_loopback() {
                Some("loopback")
            } else if a.is_link_local() {
                Some("link-local")
            } else if a.is_private() {
                Some("rfc1918")
            } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
                Some("cgnat")
            } else if a.is_unspecified() || o[0] == 0 {
                Some("unspecified")
            } else if a.is_multicast() || a.is_broadcast() {
                Some("multicast")
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            let seg0 = a.segments()[0];
            if a.is_loopback() {
                Some("loopback")
            } else if a.is_unspecified() {
                Some("unspecified")
            } else if (seg0 & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else if (seg0 & 0xfe00) == 0xfc00 {
                Some("ula")
            } else if a.is_multicast() {
                Some("multicast")
            } else {
                None
            }
        }
    }
}
