"""Specialist Security Executors Package for Drishti AI.

Compiles graph-derived attack hypotheses into bounded execution plans
and executes invariant-specific security probes strictly mediated
by the Rust Security Kernel / Policy Gate.
"""

from drishti.executors.attack_plan import (
    AttackPlan,
    AttackPlanCompiler,
    AttackPlanStep,
    CanarySecretStore,
    CanarySpec,
    CredentialBinding,
    ExecutionBudget,
    NegativeControl,
    OutputBinding,
    ParsedEndpointIdentity,
    PlanPhase,
    PlanPrecondition,
    PlanStep,
)
from drishti.executors.base import (
    BudgetExhaustedError,
    ExecutionCancelledError,
    ISpecialistExecutor,
    redact_and_bound_evidence,
    sanitize_response_headers,
)

__all__ = [
    "AttackPlan",
    "AttackPlanCompiler",
    "AttackPlanStep",
    "CanarySecretStore",
    "CanarySpec",
    "CredentialBinding",
    "ExecutionBudget",
    "NegativeControl",
    "OutputBinding",
    "ParsedEndpointIdentity",
    "PlanPhase",
    "PlanPrecondition",
    "PlanStep",
    "BudgetExhaustedError",
    "ExecutionCancelledError",
    "ISpecialistExecutor",
    "redact_and_bound_evidence",
    "sanitize_response_headers",
]
