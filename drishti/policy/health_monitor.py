"""Target health monitor and automated circuit breaker."""

import asyncio
import time
from typing import Optional
from drishti.core.config import CircuitBreakerConfig
from drishti.core.exceptions import EmergencyStopTriggered

class HealthMonitor:
    """
    Monitors target staging health, response times, and error rates.
    Triggers automated exponential backoff or emergency circuit breaking.
    """
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.consecutive_5xx_count = 0
        self.is_circuit_open = False
        self.last_trip_reason: Optional[str] = None
        self._backoff_delay = 0.5

    def record_telemetry(self, latency_ms: float, status_code: int) -> None:
        """Evaluates health telemetry from an observed response."""
        if not self.config.enabled:
            return

        # 1. 5xx Server Error Tracking
        if 500 <= status_code <= 599:
            self.consecutive_5xx_count += 1
            if self.consecutive_5xx_count >= self.config.consecutive_5xx_threshold:
                self.trip_circuit_breaker(
                    f"Target returned {self.consecutive_5xx_count} consecutive 5xx errors."
                )
        else:
            self.consecutive_5xx_count = 0

        # 2. Latency Spike Tracking
        if latency_ms >= self.config.latency_spike_threshold_ms:
            # Staging system shows strain: increase backoff delay
            self._backoff_delay = min(self._backoff_delay * 1.5, 5.0)
        else:
            self._backoff_delay = max(self._backoff_delay * 0.8, 0.1)

    async def apply_health_backoff(self) -> None:
        """Applies adaptive backoff if target shows elevated latency."""
        if self.is_circuit_open:
            raise EmergencyStopTriggered(
                f"Execution halted: Circuit breaker OPEN ({self.last_trip_reason})"
            )
        if self._backoff_delay > 0.5:
            await asyncio.sleep(self._backoff_delay)

    def trip_circuit_breaker(self, reason: str) -> None:
        self.is_circuit_open = True
        self.last_trip_reason = reason
        raise EmergencyStopTriggered(f"EMERGENCY CIRCUIT BREAKER TRIPPED: {reason}")

    def reset_circuit_breaker(self) -> None:
        self.is_circuit_open = False
        self.consecutive_5xx_count = 0
        self.last_trip_reason = None
        self._backoff_delay = 0.5
