"""Journey-Aware B2B Travel Crawler for Drishti AI.

Executes authenticated travel workflows (Search -> Quote -> Hold -> Book)
across isolated multi-tenant browser contexts (Agency A and Agency B),
mediating all network egress through the Rust Security Kernel via NetworkBridge.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from drishti.discovery.browser_context import BrowserContextManager
from drishti.discovery.crawler_models import (
    ActionType,
    BrowserObservation,
    CrawlSession,
    CrawlStatus,
    JourneyPlan,
    JourneyStep,
    RoleContext,
)
from drishti.discovery.models import CaptureCompleteness
from drishti.discovery.network_bridge import NetworkBridge

logger = logging.getLogger(__name__)


class JourneyCrawler:
    """Orchestrates journey-aware browser discovery with fail-closed security mediation."""

    def __init__(
        self,
        network_bridge: NetworkBridge,
        browser_context_mgr: Optional[BrowserContextManager] = None,
        default_timeout_seconds: int = 30,
        max_requests_per_session: int = 100,
    ):
        self.network_bridge = network_bridge
        self.context_mgr = browser_context_mgr or BrowserContextManager(network_bridge)
        self.default_timeout_seconds = default_timeout_seconds
        self.max_requests_per_session = max_requests_per_session

    async def execute_journey(
        self,
        browser: Any,
        role_context: RoleContext,
        journey_plan: JourneyPlan,
    ) -> Tuple[CrawlSession, List[BrowserObservation]]:
        """Executes a journey plan within an isolated tenant browser context.

        Returns the completed CrawlSession and all role-attributed BrowserObservations.
        """
        session_id = f"SESS-{uuid.uuid4().hex[:8].upper()}"
        session = CrawlSession(
            session_id=session_id,
            role_context=role_context,
            status=CrawlStatus.IN_PROGRESS.value,
            capture_completeness=CaptureCompleteness.PARTIAL.value,
            max_requests=min(journey_plan.max_requests, self.max_requests_per_session),
        )

        # Clear any residual observations on the bridge before starting this session
        obs_start_idx = len(self.network_bridge.observations)
        timeout_seconds = journey_plan.max_duration_seconds or self.default_timeout_seconds

        context = None
        try:
            async def _run_session() -> None:
                nonlocal context
                context = await self.context_mgr.create_isolated_context(
                    browser=browser,
                    role_context=role_context,
                    session_id=session_id,
                )
                page = await context.new_page()

                # Execute journey steps in sequence
                all_steps_succeeded = True
                for step in journey_plan.steps:
                    # Dynamically check real-time request budget before each step
                    current_obs_count = len(self.network_bridge.observations) - obs_start_idx
                    session.request_count = current_obs_count
                    if session.request_count >= session.max_requests:
                        session.status = CrawlStatus.BUDGET_EXHAUSTED.value
                        session.errors.append(f"Request budget exhausted ({session.max_requests}) at step {step.step_id}")
                        all_steps_succeeded = False
                        break

                    step_ok = await self._execute_step(page, step, role_context)
                    if step_ok:
                        session.completed_steps.append(step.step_id)
                    else:
                        all_steps_succeeded = False
                        if step.is_critical:
                            session.errors.append(f"Critical journey step {step.step_id} failed; halting journey.")
                            break

                # Capture completeness invariant: only COMPLETE if all steps succeeded without error
                if all_steps_succeeded and len(session.completed_steps) == len(journey_plan.steps):
                    session.status = CrawlStatus.COMPLETED.value
                    session.capture_completeness = CaptureCompleteness.COMPLETE.value
                else:
                    session.capture_completeness = CaptureCompleteness.PARTIAL.value
                    if session.status == CrawlStatus.IN_PROGRESS.value:
                        session.status = CrawlStatus.FAILED.value

            await asyncio.wait_for(_run_session(), timeout=timeout_seconds)

        except asyncio.TimeoutError:
            session.status = CrawlStatus.TIMEOUT.value
            session.capture_completeness = CaptureCompleteness.PARTIAL.value
            session.errors.append(f"Journey execution timed out after {timeout_seconds}s.")
        except Exception as e:
            session.status = CrawlStatus.FAILED.value
            session.capture_completeness = CaptureCompleteness.PARTIAL.value
            session.errors.append(f"Unexpected crawler error: {str(e)}")
        finally:
            session.end_time = datetime.now(timezone.utc).isoformat()
            if context:
                await self.context_mgr.close_context(session_id)

        session_observations = self.network_bridge.observations[obs_start_idx:]
        session.request_count = len(session_observations)
        return session, session_observations

    async def _execute_step(self, page: Any, step: JourneyStep, role_context: RoleContext) -> bool:
        """Executes a single JourneyStep on the browser page."""
        try:
            if step.action_type == ActionType.NAVIGATE.value:
                response = await page.goto(step.target, timeout=step.timeout_ms)
                if step.expected_status and response and response.status != step.expected_status:
                    logger.warning(
                        f"Step {step.step_id} expected status {step.expected_status}, got {response.status}"
                    )
                    return False
                return True

            elif step.action_type == ActionType.CLICK.value:
                await page.click(step.target, timeout=step.timeout_ms)
                return True

            elif step.action_type == ActionType.FILL.value:
                if step.value is not None:
                    await page.fill(step.target, step.value, timeout=step.timeout_ms)
                return True

            elif step.action_type == ActionType.API_CALL.value:
                # Dispatches an asynchronous fetch from inside the page context using parameterized arguments
                method = (step.value or "GET").upper()
                js_func = """
                async ([url, method, payload]) => {
                    const opts = {
                        method: method,
                        headers: { "Content-Type": "application/json" }
                    };
                    if (payload) {
                        opts.body = JSON.stringify(payload);
                    }
                    const res = await fetch(url, opts);
                    return res.status;
                }
                """
                status = await page.evaluate(js_func, [step.target, method, step.payload])
                if step.expected_status and status != step.expected_status:
                    logger.warning(f"Step {step.step_id} API call expected {step.expected_status}, got {status}")
                    return False
                return True

            elif step.action_type == ActionType.WAIT_FOR.value:
                await page.wait_for_selector(step.target, timeout=step.timeout_ms)
                return True

            return True

        except Exception as e:
            logger.warning(f"Error executing journey step {step.step_id} ({step.action_type}): {e}")
            return False
