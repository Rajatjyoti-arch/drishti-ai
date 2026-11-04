"""Adversarial tests proving concurrent workers cannot exceed shared rate and budget caps."""

import pytest
import asyncio
from drishti.core.config import ExecutionBudgets, RateLimitConfig, ExecutionConfig, CircuitBreakerConfig
from drishti.policy.rate_limiter import MultiBudgetRateLimiter
from drishti.core.exceptions import PolicyViolationError

@pytest.mark.asyncio
async def test_concurrent_workers_respect_global_budget():
    # Allow 10 total requests
    budgets = ExecutionBudgets(
        rate_limit=RateLimitConfig(requests_per_second=20.0, burst_capacity=20, max_concurrency=5),
        execution=ExecutionConfig(max_requests_per_test=20, max_total_requests_per_run=10)
    )
    limiter = MultiBudgetRateLimiter(budgets)

    successful_requests = 0
    denied_requests = 0

    async def worker(worker_id: int):
        nonlocal successful_requests, denied_requests
        for _ in range(5):
            try:
                await limiter.acquire(f"test_worker_{worker_id}")
                successful_requests += 1
            except PolicyViolationError:
                denied_requests += 1

    # Launch 5 concurrent workers attempting 25 total requests
    await asyncio.gather(*(worker(i) for i in range(5)))

    # Global budget was 10: exactly 10 must succeed, remainder denied
    assert successful_requests == 10
    assert denied_requests == 15
    assert limiter.get_remaining_global_budget() == 0

@pytest.mark.asyncio
async def test_concurrency_semaphore_limits_active_executions():
    # Max concurrency = 2
    budgets = ExecutionBudgets(
        rate_limit=RateLimitConfig(requests_per_second=20.0, burst_capacity=10, max_concurrency=2),
        execution=ExecutionConfig(max_requests_per_test=20, max_total_requests_per_run=50)
    )
    limiter = MultiBudgetRateLimiter(budgets)

    active_count = 0
    max_observed_active = 0

    async def simulated_task():
        nonlocal active_count, max_observed_active
        async with limiter.semaphore:
            active_count += 1
            max_observed_active = max(max_observed_active, active_count)
            await asyncio.sleep(0.05)
            active_count -= 1

    await asyncio.gather(*(simulated_task() for _ in range(6)))

    assert max_observed_active <= 2
