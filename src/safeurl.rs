//! Outbound URL policy (security.md, conformance S-SSRF-1): https only, and
//! never to a private, loopback, link-local, shared or unspecified address,
//! whatever spelling the host uses. `OBX_ALLOW_PRIVATE_URLS` (development)
//! allows private addresses and http, but link-local (cloud metadata) stays
//! blocked.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::problem::Problem;

fn v4_unsafe(ip: Ipv4Addr, allow_private: bool) -> bool {
    let o = ip.octets();
    if ip.is_link_local() {
        return true;
    }
    if allow_private {
        return false;
    }
    ip.is_loopback()
        || ip.is_private()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || o[0] >= 240
}

fn v6_unsafe(ip: Ipv6Addr, allow_private: bool) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_unsafe(v4, allow_private);
    }
    let s = ip.segments();
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    if allow_private {
        return false;
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] == 0x64 && s[1] == 0xff9b)
}

pub fn ip_unsafe(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v) => v4_unsafe(v, allow_private),
        IpAddr::V6(v) => v6_unsafe(v, allow_private),
    }
}

fn unsafe_url(detail: &str) -> Problem {
    Problem::new("unsafe_url", detail.to_string()).field("/url", "unsafe_url", detail.to_string())
}

/// Checks an outbound URL; resolves host names and checks every address.
pub async fn check(raw: &str, allow_private: bool) -> Result<url::Url, Problem> {
    let u =
        url::Url::parse(raw.trim()).map_err(|_| unsafe_url("The address is not a valid URL."))?;
    match u.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => return Err(unsafe_url("Only https:// addresses are allowed.")),
    }
    let host = match u.host() {
        Some(url::Host::Ipv4(ip)) => {
            return if v4_unsafe(ip, allow_private) {
                Err(unsafe_url("The address is not a public internet address."))
            } else {
                Ok(u)
            };
        }
        Some(url::Host::Ipv6(ip)) => {
            return if v6_unsafe(ip, allow_private) {
                Err(unsafe_url("The address is not a public internet address."))
            } else {
                Ok(u)
            };
        }
        Some(url::Host::Domain(d)) => d.trim_end_matches('.').to_lowercase(),
        None => return Err(unsafe_url("The address has no host.")),
    };
    if !allow_private
        && (host == "localhost"
            || host.ends_with(".localhost")
            || host.ends_with(".local")
            || host.ends_with(".internal"))
    {
        return Err(unsafe_url("The address is not a public internet address."));
    }
    let port = u.port_or_known_default().unwrap_or(443);
    match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            for a in addrs {
                if ip_unsafe(a.ip(), allow_private) {
                    return Err(unsafe_url(
                        "The address resolves to a private, loopback or link-local address.",
                    ));
                }
            }
            Ok(u)
        }
        Err(_) => Err(unsafe_url("The host name cannot be resolved.")),
    }
}

/// Checks a host name or address for an outbound connection (SFTP) and
/// returns the addresses to connect to: every address the name resolves to
/// must be public.
pub async fn check_host(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<std::net::SocketAddr>, Problem> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h.is_empty() {
        return Err(unsafe_url("The host is empty."));
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        if ip_unsafe(ip, allow_private) {
            return Err(unsafe_url("The address is not a public internet address."));
        }
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    // Every spelling of an IPv4 address a resolver accepts (127.1, 0x7f.1,
    // 2130706433) goes through the URL parser's normalisation.
    if let Ok(u) = url::Url::parse(&format!("https://{h}/")) {
        if let Some(url::Host::Ipv4(ip)) = u.host() {
            if v4_unsafe(ip, allow_private) {
                return Err(unsafe_url("The address is not a public internet address."));
            }
            return Ok(vec![std::net::SocketAddr::new(IpAddr::V4(ip), port)]);
        }
    } else {
        return Err(unsafe_url("The host name is not valid."));
    }
    let name = h.trim_end_matches('.').to_lowercase();
    if !allow_private && local_name(&name) {
        return Err(unsafe_url("The address is not a public internet address."));
    }
    let addrs: Vec<_> = tokio::net::lookup_host((name.as_str(), port))
        .await
        .map_err(|_| unsafe_url("The host name cannot be resolved."))?
        .collect();
    if addrs.is_empty() {
        return Err(unsafe_url("The host name cannot be resolved."));
    }
    if addrs.iter().any(|a| ip_unsafe(a.ip(), allow_private)) {
        return Err(unsafe_url(
            "The address resolves to a private, loopback or link-local address.",
        ));
    }
    Ok(addrs)
}

fn local_name(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
}

/// The synchronous part of [`check`]: scheme, literal addresses and local
/// names (redirect targets; names are checked again when they resolve).
pub fn check_literal(u: &url::Url, allow_private: bool) -> Result<(), &'static str> {
    match u.scheme() {
        "https" => {}
        "http" if allow_private => {}
        _ => return Err("Only https:// addresses are allowed."),
    }
    match u.host() {
        Some(url::Host::Ipv4(ip)) if v4_unsafe(ip, allow_private) => {
            Err("The address is not a public internet address.")
        }
        Some(url::Host::Ipv6(ip)) if v6_unsafe(ip, allow_private) => {
            Err("The address is not a public internet address.")
        }
        Some(url::Host::Domain(d))
            if !allow_private && local_name(&d.trim_end_matches('.').to_lowercase()) =>
        {
            Err("The address is not a public internet address.")
        }
        None => Err("The address has no host."),
        _ => Ok(()),
    }
}

/// A DNS resolver for outbound HTTP that refuses names resolving to a
/// private, loopback or link-local address, so a redirect or a DNS change
/// between the check and the connection cannot reach one (DNS rebinding).
#[derive(Debug, Clone, Copy)]
pub struct SafeResolver {
    pub allow_private: bool,
}

/// The error of a refused address: callers map it to unsafe_url.
#[derive(Debug)]
pub struct UnsafeAddress(pub String);

impl std::fmt::Display for UnsafeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsafe address: {}", self.0)
    }
}

impl std::error::Error for UnsafeAddress {}

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow = self.allow_private;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let lower = host.trim_end_matches('.').to_lowercase();
            if !allow && local_name(&lower) {
                return Err(
                    Box::new(UnsafeAddress(host)) as Box<dyn std::error::Error + Send + Sync>
                );
            }
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((lower.as_str(), 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                .collect();
            if addrs.iter().any(|a| ip_unsafe(a.ip(), allow)) {
                return Err(
                    Box::new(UnsafeAddress(host)) as Box<dyn std::error::Error + Send + Sync>
                );
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether a reqwest error was caused by the URL policy.
pub fn is_unsafe_error(e: &reqwest::Error) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if s.is::<UnsafeAddress>() || s.to_string().starts_with("unsafe address") {
            return true;
        }
        src = s.source();
    }
    false
}

/// An HTTP client for outbound requests under the URL policy: names are
/// resolved by [`SafeResolver`], every redirect target is checked, at most
/// `max_redirects` redirects are followed, and no proxy from the
/// environment is used.
pub fn client(
    allow_private: bool,
    timeout: std::time::Duration,
    max_redirects: usize,
) -> reqwest::Client {
    let policy = reqwest::redirect::Policy::custom(move |a| {
        if a.previous().len() >= max_redirects {
            return a.error(UnsafeAddress("too many redirects".into()));
        }
        match check_literal(a.url(), allow_private) {
            Ok(()) => a.follow(),
            Err(why) => a.error(UnsafeAddress(why.into())),
        }
    });
    reqwest::Client::builder()
        .dns_resolver(std::sync::Arc::new(SafeResolver { allow_private }))
        .redirect(policy)
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(std::time::Duration::from_secs(15))
        .user_agent(format!("{}/{}", crate::app::SOFTWARE, crate::app::VERSION))
        .build()
        .expect("http client")
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn refuses_private_spellings() {
        for u in [
            "https://169.254.169.254/latest/",
            "https://[::ffff:169.254.169.254]/",
            "https://[fe80::1]/",
            "https://2852039166/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:7f00:1]/",
            "https://0.0.0.0/",
            "https://localhost/",
            "https://10.0.0.1/",
            "https://100.64.0.1/",
            "https://[fd00::1]/",
            "https://127.1/",
            "https://0x7f000001/",
            "https://0177.0.0.1/",
            "file:///etc/passwd",
            "http://example.com/",
        ] {
            assert!(super::check(u, false).await.is_err(), "{u}");
        }
        assert!(
            super::check("https://169.254.169.254/", true)
                .await
                .is_err()
        );
        assert!(super::check("https://8.8.8.8/x.csv", false).await.is_ok());
    }

    #[tokio::test]
    async fn refuses_private_hosts() {
        for h in [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "::1",
            "[::1]",
            "localhost",
            "10.1.2.3",
            "169.254.169.254",
            "fe80::1",
            "sftp.internal",
            "",
        ] {
            assert!(super::check_host(h, 22, false).await.is_err(), "{h}");
        }
        assert!(
            super::check_host("169.254.169.254", 22, true)
                .await
                .is_err()
        );
        assert!(super::check_host("127.0.0.1", 22, true).await.is_ok());
        assert!(super::check_host("8.8.8.8", 22, false).await.is_ok());
        let u = url::Url::parse("https://[::ffff:127.0.0.1]/").unwrap();
        assert!(super::check_literal(&u, false).is_err());
        let u = url::Url::parse("http://example.com/").unwrap();
        assert!(super::check_literal(&u, false).is_err());
    }
}
