"""Authorization Contract models and loader for Drishti AI."""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
from pydantic import BaseModel, Field

class TestTenants(BaseModel):
    __test__ = False
    attacker_tenant_id: str
    victim_tenant_id: str
    subagent_tenant_id: Optional[str] = None

class AuthorizationContract(BaseModel):
    contract_version: str = "1.0.0"
    permitted_targets: List[str] = Field(..., min_length=1)
    test_tenants: TestTenants
    prohibited_actions: List[str] = Field(default_factory=list)

    @classmethod
    def load_from_file(cls, path: str | Path) -> "AuthorizationContract":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)
