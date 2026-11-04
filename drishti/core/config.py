"""Configuration loader and schema validator for Drishti AI."""

from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from pydantic import BaseModel, Field

class RateLimitConfig(BaseModel):
    requests_per_second: float = Field(default=2.0, ge=0.1, le=20.0)
    burst_capacity: int = Field(default=4, ge=1, le=50)
    max_concurrency: int = Field(default=2, ge=1, le=10)

class ExecutionConfig(BaseModel):
    timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)
    max_requests_per_test: int = Field(default=20, ge=1, le=200)
    max_total_requests_per_run: int = Field(default=250, ge=5, le=5000)
    max_retries_per_request: int = Field(default=2, ge=0, le=5)

class CircuitBreakerConfig(BaseModel):
    enabled: bool = Field(default=True)
    latency_spike_threshold_ms: int = Field(default=500, ge=50, le=10000)
    consecutive_5xx_threshold: int = Field(default=3, ge=1, le=20)

class EvidenceConfig(BaseModel):
    max_payload_size_bytes: int = Field(default=1048576) # 1 MB
    redaction_enabled: bool = Field(default=True)
    retention_days: int = Field(default=30, ge=1, le=365)

class ExecutionBudgets(BaseModel):
    version: str = "1.0.0"
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)

    @classmethod
    def load_from_yaml(cls, path: str | Path) -> "ExecutionBudgets":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data)
