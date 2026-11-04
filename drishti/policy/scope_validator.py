"""Scope validator enforcing permitted target domains, schemes, ports, and IP ranges."""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Tuple
from drishti.core.contract import AuthorizationContract
from drishti.core.exceptions import OutOfScopeError, PolicyViolationError

FORBIDDEN_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("224.0.0.0/4"),    # Multicast
    ipaddress.ip_network("::1/128"),        # IPv6 Loopback
    ipaddress.ip_network("fe80::/10"),      # IPv6 Link-local
    ipaddress.ip_network("fc00::/7"),       # IPv6 Unique Local
]

LOOPBACK_NETWORK = ipaddress.ip_network("127.0.0.0/8")

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 3000, 8000, 8080, 8443, 9000}

class ScopeValidator:
    def __init__(self, contract: AuthorizationContract):
        self.contract = contract
        self.permitted_targets = set(contract.permitted_targets)
        # Check if local loopback is explicitly whitelisted for development testing
        self.allow_local_test = any(
            t in {"localhost", "127.0.0.1", "::1"} for t in self.permitted_targets
        )

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Validates URL scheme, port, hostname, and resolves destination IP.
        Returns (is_valid, reason). Raises OutOfScopeError if invalid.
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise OutOfScopeError(f"Malformed URL '{url}': {e}")

        if parsed.scheme not in ALLOWED_SCHEMES:
            raise OutOfScopeError(
                f"Forbidden scheme '{parsed.scheme}'. Only {ALLOWED_SCHEMES} are permitted."
            )

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in ALLOWED_PORTS:
            raise OutOfScopeError(
                f"Forbidden destination port '{port}'. Permitted ports: {ALLOWED_PORTS}"
            )

        hostname = parsed.hostname
        if not hostname:
            raise OutOfScopeError(f"Missing hostname in URL '{url}'")

        # 1. Hostname allowlist match
        target_matched = any(
            hostname == target or hostname.endswith(f".{target}")
            for target in self.permitted_targets
        )
        if not target_matched:
            raise OutOfScopeError(
                f"Hostname '{hostname}' not in permitted targets: {self.permitted_targets}"
            )

        # 2. DNS Resolution & IP Range Check (Anti-SSRF & Anti-DNS Rebinding)
        try:
            resolved_ips = self.resolve_hostname(hostname)
        except Exception as e:
            raise OutOfScopeError(f"DNS resolution failure for '{hostname}': {e}")

        for ip_str in resolved_ips:
            self.validate_resolved_ip(ip_str, hostname)

        return True, "URL and resolved destination IP conform to scope policy"

    def resolve_hostname(self, hostname: str) -> List[str]:
        """Resolves hostname to IP addresses."""
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ips = list({info[4][0] for info in addr_info})
            return ips
        except socket.gaierror as e:
            raise OutOfScopeError(f"Unable to resolve DNS for {hostname}: {e}")

    def validate_resolved_ip(self, ip_str: str, hostname: str) -> None:
        """Validates that a resolved IP does not cross forbidden network boundaries."""
        ip_obj = ipaddress.ip_address(ip_str)

        # Handle loopback
        if ip_obj in LOOPBACK_NETWORK or ip_str == "::1":
            if self.allow_local_test and hostname in {"localhost", "127.0.0.1", "::1"}:
                return  # Authorized for local test fixture
            raise OutOfScopeError(
                f"Destination '{hostname}' resolved to loopback IP '{ip_str}' which is prohibited."
            )

        # Check forbidden private / internal ranges
        for net in FORBIDDEN_PRIVATE_NETWORKS:
            if ip_obj in net:
                if self.allow_local_test:
                    return # Allow local subnet during mock testing if explicitly permitted
                raise OutOfScopeError(
                    f"Destination '{hostname}' resolved to private IP '{ip_str}' in subnet {net}."
                )
