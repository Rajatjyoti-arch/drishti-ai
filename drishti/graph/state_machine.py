"""Independent entity lifecycles and state machine validation rules for B2B travel.

Models separate, non-linear lifecycles for:
- Quote (ISSUED, ACCEPTED, EXPIRED, SUPERSEDED)
- Hold (ACTIVE, CONFIRMED, EXPIRED, CANCELLED)
- Booking (PENDING, CONFIRMED, CANCELLED)
- Payment (INITIATED, AUTHORIZED, CAPTURED, FAILED)
- Refund (REQUESTED, PROCESSING, SUCCEEDED, FAILED)

Enforces Invariant I-03 (Perishable Hold Expiration) and Invariant I-04
(Payment/Refund Idempotency and Cumulative Refund Bounds).
"""

from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field


class QuoteState(str, Enum):
    ISSUED = "ISSUED"
    ACCEPTED = "ACCEPTED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"


class HoldState(str, Enum):
    ACTIVE = "ACTIVE"
    CONFIRMED = "CONFIRMED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class BookingState(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    CANCELLED = "CANCELLED"


class PaymentState(str, Enum):
    INITIATED = "INITIATED"
    AUTHORIZED = "AUTHORIZED"
    CAPTURED = "CAPTURED"
    FAILED = "FAILED"


class RefundState(str, Enum):
    REQUESTED = "REQUESTED"
    PROCESSING = "PROCESSING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class TransitionOutcome(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"


class TransitionRule(BaseModel):
    """Specification of an allowed or explicitly prohibited state transition."""
    object_type: str
    from_state: str
    to_state: str
    outcome: TransitionOutcome
    rationale: str
    bound_invariant: Optional[str] = None


# Declared transition rules across all entity lifecycles
TRANSITION_RULES: List[TransitionRule] = [
    # -------------------------------------------------------------------------
    # Quote Lifecycle Rules
    # -------------------------------------------------------------------------
    TransitionRule(
        object_type="Quote",
        from_state=QuoteState.ISSUED.value,
        to_state=QuoteState.ACCEPTED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Fare accepted and selected for holding or booking.",
    ),
    TransitionRule(
        object_type="Quote",
        from_state=QuoteState.ISSUED.value,
        to_state=QuoteState.EXPIRED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Quote validity TTL elapsed without acceptance.",
    ),
    TransitionRule(
        object_type="Quote",
        from_state=QuoteState.ISSUED.value,
        to_state=QuoteState.SUPERSEDED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="New search or re-pricing yielded an updated quote token.",
    ),
    TransitionRule(
        object_type="Quote",
        from_state=QuoteState.EXPIRED.value,
        to_state=QuoteState.ACCEPTED.value,
        outcome=TransitionOutcome.DENIED,
        rationale="Expired fare quote cannot be accepted.",
        bound_invariant="I-02-SERVER-AUTHORITATIVE-PRICING",
    ),
    TransitionRule(
        object_type="Quote",
        from_state=QuoteState.SUPERSEDED.value,
        to_state=QuoteState.ACCEPTED.value,
        outcome=TransitionOutcome.DENIED,
        rationale="Superseded quote token cannot be accepted for checkout.",
        bound_invariant="I-02-SERVER-AUTHORITATIVE-PRICING",
    ),

    # -------------------------------------------------------------------------
    # Hold Lifecycle Rules (Invariant I-03)
    # -------------------------------------------------------------------------
    TransitionRule(
        object_type="Hold",
        from_state=HoldState.ACTIVE.value,
        to_state=HoldState.CONFIRMED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Active hold converted into confirmed reservation.",
    ),
    TransitionRule(
        object_type="Hold",
        from_state=HoldState.ACTIVE.value,
        to_state=HoldState.EXPIRED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Hold TTL window elapsed; inventory released.",
    ),
    TransitionRule(
        object_type="Hold",
        from_state=HoldState.ACTIVE.value,
        to_state=HoldState.CANCELLED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Hold explicitly released prior to expiration.",
    ),
    TransitionRule(
        object_type="Hold",
        from_state=HoldState.EXPIRED.value,
        to_state=HoldState.CONFIRMED.value,
        outcome=TransitionOutcome.DENIED,
        rationale="Expired reservation hold cannot be confirmed.",
        bound_invariant="I-03-PERISHABLE-HOLD-EXPIRATION",
    ),
    TransitionRule(
        object_type="Hold",
        from_state=HoldState.CANCELLED.value,
        to_state=HoldState.CONFIRMED.value,
        outcome=TransitionOutcome.DENIED,
        rationale="Cancelled hold cannot be converted into a confirmed booking.",
        bound_invariant="I-03-PERISHABLE-HOLD-EXPIRATION",
    ),

    # -------------------------------------------------------------------------
    # Booking Lifecycle Rules
    # -------------------------------------------------------------------------
    TransitionRule(
        object_type="Booking",
        from_state=BookingState.PENDING.value,
        to_state=BookingState.CONFIRMED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Booking confirmed upon successful hold and payment authorization.",
    ),
    TransitionRule(
        object_type="Booking",
        from_state=BookingState.PENDING.value,
        to_state=BookingState.CANCELLED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Pending booking cancelled by agency or payment timeout.",
    ),
    TransitionRule(
        object_type="Booking",
        from_state=BookingState.CONFIRMED.value,
        to_state=BookingState.CANCELLED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Confirmed booking cancelled; triggers refund workflow.",
    ),
    TransitionRule(
        object_type="Booking",
        from_state=BookingState.CANCELLED.value,
        to_state=BookingState.CONFIRMED.value,
        outcome=TransitionOutcome.DENIED,
        rationale="Cancelled booking cannot be directly reinstated without re-booking.",
    ),

    # -------------------------------------------------------------------------
    # Payment Lifecycle Rules (Invariant I-04A: Idempotency)
    # -------------------------------------------------------------------------
    TransitionRule(
        object_type="Payment",
        from_state=PaymentState.INITIATED.value,
        to_state=PaymentState.AUTHORIZED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Payment intent pre-authorized by payment gateway.",
    ),
    TransitionRule(
        object_type="Payment",
        from_state=PaymentState.AUTHORIZED.value,
        to_state=PaymentState.CAPTURED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Authorized payment captured and funds committed.",
    ),
    TransitionRule(
        object_type="Payment",
        from_state=PaymentState.INITIATED.value,
        to_state=PaymentState.FAILED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Payment authorization rejected or dropped.",
    ),
    TransitionRule(
        object_type="Payment",
        from_state=PaymentState.AUTHORIZED.value,
        to_state=PaymentState.FAILED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Capture rejected or authorization expired.",
    ),
    TransitionRule(
        object_type="Payment",
        from_state=PaymentState.FAILED.value,
        to_state=PaymentState.CAPTURED.value,
        outcome=TransitionOutcome.DENIED,
        rationale="Failed payment transaction cannot be captured.",
        bound_invariant="I-04-REFUND-BOUNDS-IDEMPOTENCY",
    ),

    # -------------------------------------------------------------------------
    # Refund Lifecycle Rules (Invariant I-04B: Bounds & Idempotency)
    # -------------------------------------------------------------------------
    TransitionRule(
        object_type="Refund",
        from_state=RefundState.REQUESTED.value,
        to_state=RefundState.PROCESSING.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Refund request queued for settlement.",
    ),
    TransitionRule(
        object_type="Refund",
        from_state=RefundState.PROCESSING.value,
        to_state=RefundState.SUCCEEDED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Refund settled back to agency credit or source card.",
    ),
    TransitionRule(
        object_type="Refund",
        from_state=RefundState.PROCESSING.value,
        to_state=RefundState.FAILED.value,
        outcome=TransitionOutcome.ALLOWED,
        rationale="Refund rejected by supplier or banking gateway.",
    ),
    TransitionRule(
        object_type="Refund",
        from_state=RefundState.FAILED.value,
        to_state=RefundState.SUCCEEDED.value,
        outcome=TransitionOutcome.DENIED,
        rationale="Failed refund attempt cannot directly transition to succeeded.",
        bound_invariant="I-04-REFUND-BOUNDS-IDEMPOTENCY",
    ),
]


def get_lifecycle_transitions(object_type: str) -> List[TransitionRule]:
    """Returns all declared transition rules for a specific business object type."""
    return [r for r in TRANSITION_RULES if r.object_type.lower() == object_type.lower()]


def validate_transition(
    object_type: str,
    from_state: str,
    to_state: str,
) -> Tuple[TransitionOutcome, str, Optional[str]]:
    """Evaluates whether an entity state transition is ALLOWED, DENIED, or UNKNOWN.

    Returns:
        (outcome, rationale, bound_invariant)
    """
    for rule in TRANSITION_RULES:
        if (
            rule.object_type.lower() == object_type.lower()
            and rule.from_state.upper() == from_state.upper()
            and rule.to_state.upper() == to_state.upper()
        ):
            return rule.outcome, rule.rationale, rule.bound_invariant

    return (
        TransitionOutcome.UNKNOWN,
        f"Undeclared transition from {from_state} to {to_state} for {object_type}.",
        None,
    )


class IdempotencyRecord(BaseModel):
    """Stores metadata for an executed idempotent operation to detect replay vs conflict."""
    idempotency_key: str
    tenant_id: str
    operation: str
    payload_hash: str
    status: str = "COMPLETED"


def validate_refund_bounds(
    captured_amount: int,
    prior_refunds: List[int],
    requested_refund: int,
) -> Tuple[bool, str]:
    """Validates Invariant I-04: cumulative refunds must never exceed captured amount.

    All amounts are in minor units (e.g. cents/paise).
    """
    if captured_amount < 0:
        return False, "Captured amount cannot be negative."

    if any(r < 0 for r in prior_refunds):
        return False, "Prior refund amounts cannot be negative."

    if requested_refund <= 0:
        return False, "Refund amount must be positive."

    total_prior = sum(prior_refunds)
    remaining_refundable = captured_amount - total_prior

    if requested_refund > remaining_refundable:
        return False, (
            f"Refund violation (I-04): Requested refund {requested_refund} exceeds "
            f"remaining refundable amount {remaining_refundable} "
            f"(Captured: {captured_amount}, Prior Refunds: {total_prior})"
        )

    return True, f"Refund of {requested_refund} is within allowable limit ({remaining_refundable} remaining)."


def validate_payment_idempotency(
    idempotency_key: str,
    completed_keys: Any,
    tenant_id: Optional[str] = None,
    operation: Optional[str] = None,
    payload_hash: Optional[str] = None,
) -> Tuple[bool, str]:
    """Validates Invariant I-04: repeated operations must be idempotent and not create duplicate side effects.

    Detects payload conflicts when an existing idempotency key is reused with a different payload or context.
    """
    if isinstance(completed_keys, dict) and idempotency_key in completed_keys:
        rec = completed_keys[idempotency_key]
        if isinstance(rec, IdempotencyRecord):
            if (
                (tenant_id and rec.tenant_id != tenant_id)
                or (operation and rec.operation != operation)
                or (payload_hash and rec.payload_hash != payload_hash)
            ):
                return True, (
                    f"Idempotency conflict (I-04): Key '{idempotency_key}' reused with changed "
                    f"payload, tenant, or operation context!"
                )
        return True, f"Idempotent replay detected for key {idempotency_key}; returning existing result without state mutation."

    if isinstance(completed_keys, (set, list)) and idempotency_key in completed_keys:
        return True, f"Idempotent replay detected for key {idempotency_key}; returning existing result without state mutation."

    return False, f"Fresh idempotency key {idempotency_key}; proceeding with execution."
