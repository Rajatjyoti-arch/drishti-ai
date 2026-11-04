"""Browser route interceptor preventing Playwright from accessing out-of-scope targets."""

from typing import Optional
from drishti.policy.scope_validator import ScopeValidator
from drishti.core.exceptions import OutOfScopeError
from drishti.audit.ledger import TamperEvidentLedger
from drishti.audit.hash_chain import sha256_digest

class BrowserGuard:
    """
    Enforces the Authorization Contract on headless browser engines (Playwright).
    Intercepts every outbound request before the browser socket initiates.
    """
    def __init__(self, scope_validator: ScopeValidator, ledger: Optional[TamperEvidentLedger] = None):
        self.scope_validator = scope_validator
        self.ledger = ledger

    async def intercept_route(self, route, request) -> None:
        """
        Playwright route interception handler:
        await context.route("**/*", browser_guard.intercept_route)
        """
        url = request.url
        try:
            self.scope_validator.validate_url(url)
            # Request conforms to scope: permit browser to proceed
            await route.continue_()
        except OutOfScopeError as e:
            # Request attempts to reach forbidden destination: abort immediately
            if self.ledger:
                digest = sha256_digest(f"BROWSER_BLOCKED:{request.method}:{url}")
                self.ledger.record_event(
                    event_id=f"browser_abort_{hash(url) & 0xffffffff:x}",
                    event_type="BROWSER_POLICY_DENY",
                    payload_digest=digest,
                    metadata={"url": url, "reason": str(e)}
                )
            await route.abort("blockedbyclient")
