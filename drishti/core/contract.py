"""Authorization Contract models and loader for Drishti AI."""

from typing import List, Dict, Any
from pathlib import Path
import json

try:
    from pydantic import BaseModel, Field

    class RequestBudgets(BaseModel):
        max_requests_per_second: float = Field(default=5.0, ge=0.1, le=10.0)
        max_concurrent_connections: int = Field(default=2, ge=1, le=5)
        max_total_requests_per_run: int = Field(default=250, ge=10, le=1000)

    class EmergencyStopTriggers(BaseModel):
        latency_spike_threshold_ms: int = Field(default=500)
        consecutive_5xx_threshold: int = Field(default=3)
        out_of_scope_attempt_action: str = Field(default="IMMEDIATE_TERMINATE")

    class AuthorizationContract(BaseModel):
        contract_version: str = "1.0.0"
        permitted_targets: List[str]
        test_tenants: Dict[str, str]
        request_budgets: RequestBudgets
        prohibited_actions: List[str]
        emergency_stop_triggers: EmergencyStopTriggers

        @classmethod
        def load_from_file(cls, path: str | Path) -> "AuthorizationContract":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls(**data)

except ImportError:
    # Graceful fallback to dataclasses when dependencies are not yet installed
    from dataclasses import dataclass

    @dataclass
    class RequestBudgets:
        max_requests_per_second: float = 5.0
        max_concurrent_connections: int = 2
        max_total_requests_per_run: int = 250

    @dataclass
    class EmergencyStopTriggers:
        latency_spike_threshold_ms: int = 500
        consecutive_5xx_threshold: int = 3
        out_of_scope_attempt_action: str = "IMMEDIATE_TERMINATE"

    @dataclass
    class AuthorizationContract:
        contract_version: str
        permitted_targets: List[str]
        test_tenants: Dict[str, str]
        request_budgets: RequestBudgets
        prohibited_actions: List[str]
        emergency_stop_triggers: EmergencyStopTriggers

        @classmethod
        def load_from_file(cls, path: str | Path) -> "AuthorizationContract":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            budgets = RequestBudgets(**data["request_budgets"])
            triggers = EmergencyStopTriggers(**data["emergency_stop_triggers"])
            return cls(
                contract_version=data.get("contract_version", "1.0.0"),
                permitted_targets=data["permitted_targets"],
                test_tenants=data["test_tenants"],
                request_budgets=budgets,
                prohibited_actions=data["prohibited_actions"],
                emergency_stop_triggers=triggers
            )
