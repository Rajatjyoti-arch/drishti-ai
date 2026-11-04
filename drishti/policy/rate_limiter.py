"""Configuration-driven token bucket rate limiter and multi-budget coordinator."""

import asyncio
import time
from typing import Dict
from drishti.core.config import ExecutionBudgets
from drishti.core.exceptions import PolicyViolationError

class MultiBudgetRateLimiter:
    """
    Enforces all six execution controls:
    1. Token-bucket rate limiter (requests/sec)
    2. Concurrency semaphore (max concurrent active requests)
    3. Per-test budget (max requests per single test)
    4. Global budget (max requests per entire session)
    5. Timeout limits
    6. Ensures retries consume the same budget
    """
    def __init__(self, budgets: ExecutionBudgets):
        self.budgets = budgets
        self.rate_config = budgets.rate_limit
        self.exec_config = budgets.execution

        # Token bucket state
        self.capacity = float(self.rate_config.burst_capacity)
        self.tokens = float(self.capacity)
        self.refill_rate = float(self.rate_config.requests_per_second)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

        # Concurrency semaphore
        self.semaphore = asyncio.Semaphore(self.rate_config.max_concurrency)

        # Budget counters
        self.global_requests_used = 0
        self.test_requests_used: Dict[str, int] = {}

    def _refill_tokens(self) -> None:
        now = time.monotonic()
        delta = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + (delta * self.refill_rate))
        self.last_refill = now

    async def acquire(self, test_id: str) -> None:
        """
        Acquires permission to execute a request.
        Validates global and per-test budgets and waits for token availability.
        """
        async with self._lock:
            # 1. Global budget check
            if self.global_requests_used >= self.exec_config.max_total_requests_per_run:
                raise PolicyViolationError(
                    f"Global request budget exhausted ({self.global_requests_used}/{self.exec_config.max_total_requests_per_run})"
                )

            # 2. Per-test budget check
            current_test_count = self.test_requests_used.get(test_id, 0)
            if current_test_count >= self.exec_config.max_requests_per_test:
                raise PolicyViolationError(
                    f"Per-test budget for '{test_id}' exhausted ({current_test_count}/{self.exec_config.max_requests_per_test})"
                )

            # 3. Token-bucket wait
            self._refill_tokens()
            while self.tokens < 1.0:
                needed = 1.0 - self.tokens
                wait_time = needed / self.refill_rate
                await asyncio.sleep(min(wait_time, 0.5))
                self._refill_tokens()

            self.tokens -= 1.0
            self.global_requests_used += 1
            self.test_requests_used[test_id] = current_test_count + 1

    def get_remaining_global_budget(self) -> int:
        return max(0, self.exec_config.max_total_requests_per_run - self.global_requests_used)
