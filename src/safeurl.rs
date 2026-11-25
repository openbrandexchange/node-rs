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

/// A resolver that refuses host names resolving to an unsafe address. The
/// HTTP client connects only to the addresses it returns, so a name cannot
/// pass `check` and then resolve to a private address at connect time
/// (DNS rebinding).
struct SafeResolver {
    allow_private: bool,
}

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.allow_private;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addrs.is_empty() || addrs.iter().any(|a| ip_unsafe(a.ip(), allow_private)) {
                return Err(Box::new(Refused) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The error of a connection refused by the URL policy.
#[derive(Debug)]
pub struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("refused: the URL resolves to a private address")
    }
}

impl std::error::Error for Refused {}

/// True when err (or its source chain) is a policy refusal.
pub fn is_refused(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut e: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(x) = e {
        if x.is::<Refused>() {
            return true;
        }
        e = x.source();
    }
    false
}

/// An outbound HTTP client under the URL policy: no redirects, a timeout,
/// and every resolved address checked when connecting. IP-literal URLs
/// bypass the resolver, so callers run `check` on the URL first.
pub fn client(allow_private: bool, timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout.min(std::time::Duration::from_secs(10)))
        .dns_resolver(std::sync::Arc::new(SafeResolver { allow_private }))
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
}
