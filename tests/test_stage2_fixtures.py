"""Differential integration test suite verifying Vulnerable vs Patched travel service implementations."""

import pytest
import httpx
from tests.fixtures.vulnerable_app import create_vulnerable_app
from tests.fixtures.patched_app import create_patched_app

AGENCY_A_AUTH = {"Authorization": "Bearer mock_jwt_agency_a_admin_token"}
AGENCY_B_AUTH = {"Authorization": "Bearer mock_jwt_agency_b_admin_token"}

@pytest.fixture
def vulnerable_client():
    app = create_vulnerable_app()
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")

@pytest.fixture
def patched_client():
    app = create_patched_app()
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")

@pytest.mark.asyncio
async def test_differential_bola_cross_tenant_access(vulnerable_client, patched_client):
    # Setup: Agency A creates hold and booking with unique canary
    async def create_booking_for_a(client):
        hold_res = await client.post("/api/v2/holds", json={"quote_id": "QT_GOA_501"}, headers=AGENCY_A_AUTH)
        assert hold_res.status_code == 200
        hold_token = hold_res.json()["hold_token"]

        book_res = await client.post(
            "/api/v2/bookings",
            json={
                "hold_token": hold_token,
                "passenger_name": "Canary Passenger Alice",
                "passenger_passport": "Z1234567"
            },
            headers=AGENCY_A_AUTH
        )
        assert book_res.status_code == 200
        return book_res.json()

    # 1. Against Vulnerable App
    booking_a_vuln = await create_booking_for_a(vulnerable_client)
    vuln_b_res = await vulnerable_client.get(
        f"/api/v2/bookings/{booking_a_vuln['booking_id']}",
        headers=AGENCY_B_AUTH
    )
    # Flaw: Vulnerable app returns 200 and exposes Agency A's canary!
    assert vuln_b_res.status_code == 200
    assert vuln_b_res.json()["canary_token"] == booking_a_vuln["canary_token"]
    assert vuln_b_res.json()["passenger_name"] == "Canary Passenger Alice"

    # 2. Against Patched App
    booking_a_patched = await create_booking_for_a(patched_client)
    patched_b_res = await patched_client.get(
        f"/api/v2/bookings/{booking_a_patched['booking_id']}",
        headers=AGENCY_B_AUTH
    )
    # Secure: Patched app returns 403 Forbidden; canary is never exposed!
    assert patched_b_res.status_code == 403
    assert "Access Denied" in patched_b_res.json()["detail"]

    # Agency A can still read its own booking cleanly
    own_res = await patched_client.get(
        f"/api/v2/bookings/{booking_a_patched['booking_id']}",
        headers=AGENCY_A_AUTH
    )
    assert own_res.status_code == 200
    assert own_res.json()["booking_id"] == booking_a_patched["booking_id"]

@pytest.mark.asyncio
async def test_differential_unauthorized_mutation(vulnerable_client, patched_client):
    # Setup: Agency A creates booking
    async def create_booking_for_a(client):
        hold_res = await client.post("/api/v2/holds", json={"quote_id": "QT_GOA_501"}, headers=AGENCY_A_AUTH)
        hold_token = hold_res.json()["hold_token"]
        book_res = await client.post(
            "/api/v2/bookings",
            json={"hold_token": hold_token, "passenger_name": "Original Name", "passenger_passport": "A111"},
            headers=AGENCY_A_AUTH
        )
        return book_res.json()["booking_id"]

    # 1. Against Vulnerable App: Agency B successfully mutates Agency A's passenger name!
    b_id_vuln = await create_booking_for_a(vulnerable_client)
    patch_vuln = await vulnerable_client.patch(
        f"/api/v2/bookings/{b_id_vuln}",
        json={"passenger_name": "Tampered By B"},
        headers=AGENCY_B_AUTH
    )
    assert patch_vuln.status_code == 200
    assert patch_vuln.json()["passenger_name"] == "Tampered By B"

    # 2. Against Patched App: Agency B mutation rejected with 403
    b_id_patched = await create_booking_for_a(patched_client)
    patch_patched = await patched_client.patch(
        f"/api/v2/bookings/{b_id_patched}",
        json={"passenger_name": "Tampered By B"},
        headers=AGENCY_B_AUTH
    )
    assert patch_patched.status_code == 403
    assert "Access Denied" in patch_patched.json()["detail"]

@pytest.mark.asyncio
async def test_differential_pricing_tampering(vulnerable_client, patched_client):
    # Quote is 18,000 INR (1800000 minor units). Attacker sends 100 minor units (1 INR)
    async def attempt_price_tamper(client):
        hold_res = await client.post("/api/v2/holds", json={"quote_id": "QT_GOA_501"}, headers=AGENCY_A_AUTH)
        hold_token = hold_res.json()["hold_token"]
        return await client.post(
            "/api/v2/bookings",
            json={
                "hold_token": hold_token,
                "passenger_name": "Budget Bob",
                "passenger_passport": "B222",
                "client_amount_minor_units": 100, # Price Tampering
                "client_currency": "INR"
            },
            headers=AGENCY_A_AUTH
        )

    # 1. Against Vulnerable App: Server accepts client-controlled price!
    res_vuln = await attempt_price_tamper(vulnerable_client)
    assert res_vuln.status_code == 200
    assert res_vuln.json()["amount_minor_units"] == 100 # Flaw confirmed!

    # 2. Against Patched App: Server detects mismatch and rejects with 400!
    res_patched = await attempt_price_tamper(patched_client)
    assert res_patched.status_code == 400
    assert "Price tampering detected" in res_patched.json()["detail"]

@pytest.mark.asyncio
async def test_differential_currency_tampering(vulnerable_client, patched_client):
    # Attacker attempts to change currency from INR to IDR
    async def attempt_currency_tamper(client):
        hold_res = await client.post("/api/v2/holds", json={"quote_id": "QT_GOA_501"}, headers=AGENCY_A_AUTH)
        hold_token = hold_res.json()["hold_token"]
        return await client.post(
            "/api/v2/bookings",
            json={
                "hold_token": hold_token,
                "passenger_name": "Currency Charlie",
                "passenger_passport": "C333",
                "client_currency": "IDR" # Currency Tampering
            },
            headers=AGENCY_A_AUTH
        )

    # 1. Against Vulnerable App: Server accepts manipulated currency!
    res_vuln = await attempt_currency_tamper(vulnerable_client)
    assert res_vuln.status_code == 200
    assert res_vuln.json()["currency"] == "IDR"

    # 2. Against Patched App: Server rejects mismatched currency!
    res_patched = await attempt_currency_tamper(patched_client)
    assert res_patched.status_code == 400
    assert "Currency tampering detected" in res_patched.json()["detail"]
