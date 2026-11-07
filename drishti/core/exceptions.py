"""Core exceptions for Drishti AI."""

class DrishtiError(Exception):
    """Base exception for all Drishti errors."""
    pass

class PolicyViolationError(DrishtiError):
    """Raised when an action violates the Authorization Contract or Safety Policy."""
    pass

class OutOfScopeError(PolicyViolationError):
    """Raised when an attempted target host or URL is not in the permitted allowlist."""
    pass

class EmergencyStopTriggered(DrishtiError):
    """Raised when health thresholds are breached and testing is halted immediately."""
    pass

class BudgetExhaustedError(DrishtiError):
    """Raised when an executor breaches its configured request count, duration, or payload budget."""
    pass

class ExecutionCancelledError(DrishtiError):
    """Raised when an active security execution is terminated by emergency stop."""
    pass
