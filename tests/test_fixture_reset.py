"""Repeatability and isolation tests verifying deterministic environment reset."""

import pytest
import httpx
from tests.fixtures.mock_travel_api import create_travel_app, BaseTravelService

AUTH = {"Authorization": "Bearer mock_jwt_agency_a_admin_token"}

@pytest.fixture
def test_client():
    app = create_travel_app(BaseTravelService())
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")

@pytest.mark.asyncio
async def test_fixture_reset_restores_clean_baseline(test_client):
    # 1. Create a hold
    hold_res = await test_client.post("/api/v2/holds", json={"quote_id": "QT_GOA_501"}, headers=AUTH)
    assert hold_res.status_code == 200
    hold_token = hold_res.json()["hold_token"]

    # 2. Reset the environment
    reset_res = await test_client.post("/api/v2/reset")
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "RESET_SUCCESS"

    # 3. Verify the previous hold token is completely purged
    verify_hold_res = await test_client.post("/api/v2/holds", json={"quote_id": "NON_EXISTENT"}, headers=AUTH)
    assert verify_hold_res.status_code == 404
