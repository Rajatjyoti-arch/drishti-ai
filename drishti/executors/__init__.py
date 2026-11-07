"""Specialist Security Executors Package for Drishti AI.

Compiles graph-derived attack hypotheses into bounded execution plans
and executes invariant-specific security probes strictly mediated
by the Rust Security Kernel / Policy Gate.
"""

from drishti.executors.attack_plan import (
    AttackPlan,
    AttackPlanCompiler,
    AttackPlanStep,
    CanarySpec,
    CredentialBinding,
    ExecutionBudget,
    NegativeControl,
    PlanPhase,
    PlanPrecondition,
)
from drishti.executors.base import (
    BudgetExhaustedError,
    ExecutionCancelledError,
    ISpecialistExecutor,
    redact_and_bound_evidence,
)

__all__ = [
    "AttackPlan",
    "AttackPlanCompiler",
    "AttackPlanStep",
    "CanarySpec",
    "CredentialBinding",
    "ExecutionBudget",
    "NegativeControl",
    "PlanPhase",
    "PlanPrecondition",
    "BudgetExhaustedError",
    "ExecutionCancelledError",
    "ISpecialistExecutor",
    "redact_and_bound_evidence",
]
