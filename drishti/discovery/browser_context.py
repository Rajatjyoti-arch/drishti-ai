"""Isolated Multi-Tenant Browser Context Manager.

Creates and manages separate, isolated Playwright browser contexts for Agency A
and Agency B, ensuring cookies, local storage, session state, and credentials
are strictly partitioned and all network egress is routed through the NetworkBridge.
"""

import logging
from typing import Any, Dict, Optional
from drishti.discovery.crawler_models import RoleContext
from drishti.discovery.network_bridge import NetworkBridge

logger = logging.getLogger(__name__)


class BrowserContextManager:
    """Manages isolated browser contexts for multi-tenant B2B travel testing.

    Ensures that Agency A and Agency B contexts maintain separate cookies,
    storage state, and authentication tokens, and binds the NetworkBridge
    to intercept all context-level network activity.
    """

    def __init__(self, network_bridge: NetworkBridge, ignore_https_errors: bool = False):
        self.network_bridge = network_bridge
        self.ignore_https_errors = ignore_https_errors
        self.active_contexts: Dict[str, Any] = {}
        self._role_to_session: Dict[str, str] = {}

    async def create_isolated_context(
        self,
        browser: Any,
        role_context: RoleContext,
        session_id: str,
        current_step_id: Optional[str] = None,
        ignore_https_errors: Optional[bool] = None,
    ) -> Any:
        """Initializes a new isolated Playwright BrowserContext for a specific tenant/role.

        Configures:
        - Separate cookie jar and storage state.
        - Custom user agent if provided.
        - NetworkBridge route interception on all outbound requests (**/*).
        """
        allow_insecure = self.ignore_https_errors if ignore_https_errors is None else ignore_https_errors
        context_options: Dict[str, Any] = {
            "ignore_https_errors": allow_insecure,
        }
        if role_context.user_agent:
            context_options["user_agent"] = role_context.user_agent

        # 1. Create independent browser context
        context = await browser.new_context(**context_options)

        # 2. Inject initial role cookies if provided
        if role_context.cookies:
            await context.add_cookies(role_context.cookies)

        # 3. Bind route interception to mediate all network operations through Rust Guard
        async def route_handler(route: Any, request: Any) -> None:
            await self.network_bridge.handle_route(
                route=route,
                request=request,
                role_context=role_context,
                session_id=session_id,
                journey_step_id=current_step_id,
            )

        await context.route("**/*", route_handler)

        self.active_contexts[session_id] = context
        self._role_to_session[role_context.role_identifier] = session_id
        return context

    async def close_context(self, identifier: str) -> None:
        """Closes and releases an active browser context by session_id or role_identifier."""
        context = self.active_contexts.pop(identifier, None)
        if not context and identifier in self._role_to_session:
            sess_id = self._role_to_session.pop(identifier, None)
            if sess_id:
                context = self.active_contexts.pop(sess_id, None)
        if context:
            try:
                await context.close()
            except Exception as e:
                logger.warning(f"Error closing browser context for {identifier}: {e}")

    async def close_all(self) -> None:
        """Closes all active browser contexts."""
        for role_id in list(self.active_contexts.keys()):
            await self.close_context(role_id)
