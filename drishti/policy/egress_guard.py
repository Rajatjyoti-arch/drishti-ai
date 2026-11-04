"""Egress guard enforcing network-level destination boundaries and redirect safety."""

from urllib.parse import urljoin
from drishti.policy.scope_validator import ScopeValidator
from drishti.core.exceptions import OutOfScopeError

class EgressGuard:
    """
    Network-level destination enforcement.
    Validates destination targets and inspects every redirect before following.
    """
    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator

    def validate_request_target(self, url: str) -> None:
        """Enforces scope validation before socket initiation."""
        self.scope_validator.validate_url(url)

    def validate_redirect(self, current_url: str, location_header: str) -> str:
        """
        Validates HTTP 3xx redirect destinations.
        Prevents redirect-based SSRF or leaving authorized staging domains.
        """
        # Resolve relative redirects
        resolved_target = urljoin(current_url, location_header)
        try:
            self.scope_validator.validate_url(resolved_target)
        except OutOfScopeError as e:
            raise OutOfScopeError(
                f"Redirect from '{current_url}' to '{resolved_target}' was BLOCKED by EgressGuard: {e}"
            )
        return resolved_target
