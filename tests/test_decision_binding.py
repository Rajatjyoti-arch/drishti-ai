"""Adversarial tests proving PolicyDecision binds cryptographically to the exact request."""

import pytest
import hashlib
from drishti.core.models import OutgoingTestRequest, InvariantType, PolicyAction
from drishti.policy.gate import PolicyGate
from drishti.core.contract import AuthorizationContract, TestTenants
from drishti.core.config import ExecutionBudgets
from drishti.audit.ledger import TamperEvidentLedger

@pytest.fixture
def policy_gate(tmp_path):
    contract = AuthorizationContract(
        permitted_targets=["localhost", "127.0.0.1"],
        test_tenants=TestTenants(attacker_tenant_id="AG_A", victim_tenant_id="AG_B")
    )
    budgets = ExecutionBudgets()
    ledger = TamperEvidentLedger(db_path=tmp_path / "binding_test.db")
    return PolicyGate(contract, budgets, ledger)

@pytest.mark.asyncio
async def test_decision_is_cryptographically_unique_per_request(policy_gate):
    req_a = OutgoingTestRequest(
        method="GET",
        url="http://127.0.0.1:8000/api/v2/booking/101",
        target_tenant_id="AG_A",
        target_invariant=InvariantType.TENANT_ISOLATION
    )
    req_b = OutgoingTestRequest(
        method="POST",
        url="http://127.0.0.1:8000/api/v2/booking/101",
        body={"action": "cancel"},
        target_tenant_id="AG_A",
        target_invariant=InvariantType.TENANT_ISOLATION
    )

    dec_a = await policy_gate.evaluate_request(req_a)
    dec_b = await policy_gate.evaluate_request(req_b)

    assert dec_a.approved is True
    assert dec_b.approved is True
    # Distinct decision IDs generated
    assert dec_a.decision_id != dec_b.decision_id

    # Verify both are recorded distinctly in tamper-evident ledger
    events = policy_gate.ledger.get_all_events()
    assert len(events) == 2
    assert events[0].event_id == dec_a.decision_id
    assert events[1].event_id == dec_b.decision_id
    assert events[0].payload_digest != events[1].payload_digest
