//! DNS-aware Scope Validator and IP Destination Boundary Enforcement.
//!
//! Prevents SSRF, DNS-rebinding (TOCTOU), and unauthorized egress by validating
//! schemes, ports, hostnames, and resolving all DNS targets down to safe, non-private IP addresses.
//! Returns a pinned `ResolvedTarget` so transport connects directly to the validated IP.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use url::Url;

/// Scope validation rules configured from the Authorization Contract.
#[derive(Debug, Clone)]
pub struct ScopeValidator {
    /// Allowed domain suffixes (e.g., "staging.tbo.com", "localhost")
    pub allowed_domains: HashSet<String>,
    /// Allowed URL schemes (typically "https", or "http" for mock testing)
    pub allowed_schemes: HashSet<String>,
    /// Allowed destination TCP ports (e.g., 80, 443, 8000)
    pub allowed_ports: HashSet<u16>,
    /// Whether to permit loopback destinations (strictly for local mock travel testing)
    pub allow_loopback: bool,
    /// Explicitly permitted private staging CIDRs/IPs
    pub permitted_private_ips: HashSet<IpAddr>,
}

/// Fully resolved and validated network target ready for socket connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// Original target URL string
    pub original_url: Url,
    /// Host header value to preserve TLS certificate verification
    pub host_header: String,
    /// Cryptographically pinned destination socket address
    pub destination_addr: SocketAddr,
    /// Scheme (http or https)
    pub scheme: String,
}

impl ScopeValidator {
    /// Creates a new ScopeValidator with strict defaults.
    pub fn new() -> Self {
        let mut allowed_schemes = HashSet::new();
        allowed_schemes.insert("https".to_string());

        let mut allowed_ports = HashSet::new();
        allowed_ports.insert(443);

        Self {
            allowed_domains: HashSet::new(),
            allowed_schemes,
            allowed_ports,
            allow_loopback: false,
            permitted_private_ips: HashSet::new(),
        }
    }

    /// Builder method to add an allowed domain or subdomain.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.allowed_domains.insert(domain.into().to_lowercase());
        self
    }

    /// Builder method to permit a scheme.
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.allowed_schemes.insert(scheme.into().to_lowercase());
        self
    }

    /// Builder method to permit a port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.allowed_ports.insert(port);
        self
    }

    /// Permits loopback addresses strictly for local simulation/mock targets.
    pub fn with_loopback_allowed(mut self, allowed: bool) -> Self {
        self.allow_loopback = allowed;
        self
    }

    /// Validates a target URL and resolves its DNS to safe, non-private IP addresses.
    /// Returns the first validated socket address pinned to prevent DNS rebinding.
    pub fn validate_and_resolve(&self, target_url: &str) -> Result<ResolvedTarget, ScopeError> {
        let parsed_url = Url::parse(target_url).map_err(|e| ScopeError::InvalidUrl(e.to_string()))?;

        // 1. Validate Scheme
        let scheme = parsed_url.scheme().to_lowercase();
        if !self.allowed_schemes.contains(&scheme) {
            return Err(ScopeError::ForbiddenScheme(scheme));
        }

        // 2. Validate Port
        let port = parsed_url
            .port_or_known_default()
            .ok_or_else(|| ScopeError::MissingPort)?;
        if !self.allowed_ports.contains(&port) {
            return Err(ScopeError::ForbiddenPort(port));
        }

        // 3. Validate Host Header / Domain Allowlist
        let host_str = parsed_url
            .host_str()
            .ok_or_else(|| ScopeError::MissingHost)?
            .to_lowercase();

        if !self.is_domain_allowed(&host_str) {
            return Err(ScopeError::DomainNotAllowed(host_str));
        }

        // 4. DNS Resolution & Native IP Classification
        let socket_addrs = format!("{}:{}", host_str, port)
            .to_socket_addrs()
            .map_err(|e| ScopeError::DnsResolutionFailed(e.to_string()))?;

        let mut validated_addr: Option<SocketAddr> = None;

        for addr in socket_addrs {
            let ip = addr.ip();

            // Normalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
            let canonical_ip = normalize_ip(ip);

            // Check if address is permitted private staging address
            if self.permitted_private_ips.contains(&canonical_ip) {
                validated_addr = Some(addr);
                break;
            }

            // Check loopback
            if canonical_ip.is_loopback() {
                if !self.allow_loopback {
                    return Err(ScopeError::SsrfLoopbackRejected(canonical_ip.to_string()));
                }
                validated_addr = Some(addr);
                break;
            }

            // Reject private, link-local, multicast, or reserved ranges
            if is_private_or_restricted(canonical_ip) {
                return Err(ScopeError::SsrfPrivateIpRejected(canonical_ip.to_string()));
            }

            validated_addr = Some(addr);
            break;
        }

        let destination_addr = validated_addr.ok_or(ScopeError::NoValidDnsResults)?;

        Ok(ResolvedTarget {
            original_url: parsed_url,
            host_header: host_str,
            destination_addr,
            scheme,
        })
    }

    /// Checks if a hostname matches any configured allowed domain (exact or wildcard).
    fn is_domain_allowed(&self, host: &str) -> bool {
        for pattern in &self.allowed_domains {
            if pattern == host {
                return true;
            }
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if host == suffix || host.ends_with(&format!(".{}", suffix)) {
                    return true;
                }
            }
        }
        false
    }
}

/// Normalizes IPv4-mapped IPv6 addresses to pure IPv4.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Checks whether an IP address belongs to private, link-local, multicast, or reserved spaces.
fn is_private_or_restricted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.octets()[0] == 0 // 0.0.0.0/8 current network
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0) // IETF protocol assignments
                || (v4.octets()[0] >= 240) // Reserved for future use (240.0.0.0/4)
        }
        IpAddr::V6(v6) => {
            v6.is_multicast()
                || v6.is_unicast_link_local()
                // Unique Local Addresses (fc00::/7)
                || (v6.segments()[0] & 0xfe00 == 0xfc00)
                // IPv4-compatible (deprecated)
                || (v6.segments()[0..6] == [0, 0, 0, 0, 0, 0] && v6.segments()[6] != 0 && v6.segments()[6] != 0xffff)
        }
    }
}

/// Scope and destination validation errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("Malformed target URL: {0}")]
    InvalidUrl(String),
    #[error("URL scheme '{0}' is not authorized by policy")]
    ForbiddenScheme(String),
    #[error("Destination port {0} is not in authorized ports allowlist")]
    ForbiddenPort(u16),
    #[error("Target URL is missing a valid destination port")]
    MissingPort,
    #[error("Target URL is missing a valid destination host")]
    MissingHost,
    #[error("Target domain '{0}' does not match authorized scope allowlist")]
    DomainNotAllowed(String),
    #[error("DNS resolution failed for target: {0}")]
    DnsResolutionFailed(String),
    #[error("DNS query returned zero valid IP addresses")]
    NoValidDnsResults,
    #[error("SSRF Protection: Loopback destination '{0}' is prohibited")]
    SsrfLoopbackRejected(String),
    #[error("SSRF Protection: Private/Reserved destination IP '{0}' is prohibited")]
    SsrfPrivateIpRejected(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_scope_allows_permitted_target() {
        let validator = ScopeValidator::new()
            .with_domain("api.github.com")
            .with_scheme("https")
            .with_port(443);

        let res = validator.validate_and_resolve("https://api.github.com/repos");
        assert!(res.is_ok());
        let target = res.unwrap();
        assert_eq!(target.host_header, "api.github.com");
        assert_eq!(target.destination_addr.port(), 443);
    }

    #[test]
    fn test_scope_rejects_unauthorized_domain() {
        let validator = ScopeValidator::new()
            .with_domain("staging.tbo.com")
            .with_scheme("https")
            .with_port(443);

        let res = validator.validate_and_resolve("https://evil-attacker.com/steal");
        assert_eq!(
            res,
            Err(ScopeError::DomainNotAllowed("evil-attacker.com".to_string()))
        );
    }

    #[test]
    fn test_scope_rejects_forbidden_scheme_and_port() {
        let validator = ScopeValidator::new()
            .with_domain("api.github.com")
            .with_scheme("https")
            .with_port(443);

        // Plain HTTP forbidden
        let err_scheme = validator.validate_and_resolve("http://api.github.com/test");
        assert_eq!(err_scheme, Err(ScopeError::ForbiddenScheme("http".to_string())));

        // Forbidden port
        let err_port = validator.validate_and_resolve("https://api.github.com:8443/test");
        assert_eq!(err_port, Err(ScopeError::ForbiddenPort(8443)));
    }

    #[test]
    fn test_ssrf_rejects_loopback_unless_explicitly_permitted() {
        let validator = ScopeValidator::new()
            .with_domain("127.0.0.1")
            .with_scheme("http")
            .with_port(8000)
            .with_loopback_allowed(false); // Disallow loopback

        let res = validator.validate_and_resolve("http://127.0.0.1:8000/api/v1/book");
        assert!(matches!(res, Err(ScopeError::SsrfLoopbackRejected(_))));

        // When explicitly allowed for local testing
        let test_validator = validator.with_loopback_allowed(true);
        let allowed = test_validator.validate_and_resolve("http://127.0.0.1:8000/api/v1/book");
        assert!(allowed.is_ok());
    }

    #[test]
    fn test_ipv4_mapped_ipv6_loopback_detection() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)); // ::ffff:127.0.0.1
        let normalized = normalize_ip(mapped);
        assert_eq!(normalized, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(normalized.is_loopback());
    }
}
