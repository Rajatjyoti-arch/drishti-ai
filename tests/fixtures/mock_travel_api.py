"""Foundational mock B2B travel simulator with shared contracts, personas, and canary fixtures."""

import time
import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, Header, HTTPException, Depends, status

# Synthetic Tenant Tokens
TOKEN_MAP = {
    "Bearer mock_jwt_agency_a_admin_token": {
        "tenant_id": "AG_MUMBAI_01",
        "role": "AGENCY_ADMIN",
        "agency_name": "Apex Travel Mumbai"
    },
    "Bearer mock_jwt_agency_b_admin_token": {
        "tenant_id": "AG_DELHI_02",
        "role": "AGENCY_ADMIN",
        "agency_name": "Bharat Tours Delhi"
    },
    "Bearer mock_jwt_subagent_token": {
        "tenant_id": "SUB_MUMBAI_01A",
        "parent_tenant_id": "AG_MUMBAI_01",
        "role": "SUB_AGENT",
        "agency_name": "Apex Sub-Agent Andheri"
    }
}

class SessionContext(BaseModel):
    tenant_id: str
    role: str
    agency_name: str
    parent_tenant_id: Optional[str] = None

class SearchRequest(BaseModel):
    destination: str
    check_in: str
    nights: int = 2

class Quote(BaseModel):
    quote_id: str
    destination: str
    hotel_name: str
    room_type: str
    amount_minor_units: int # e.g. 1500000 = 15,000.00 INR
    currency: str = "INR"
    expires_at: float

class HoldRequest(BaseModel):
    quote_id: str

class Hold(BaseModel):
    hold_token: str
    quote_id: str
    tenant_id: str
    status: str = "HELD"
    expires_at: float

class BookingRequest(BaseModel):
    hold_token: str
    passenger_name: str
    passenger_passport: str
    # Client may attempt to supply overridden price/currency
    client_amount_minor_units: Optional[int] = None
    client_currency: Optional[str] = None

class Booking(BaseModel):
    booking_id: str
    hold_token: str
    owner_tenant_id: str
    status: str = "CONFIRMED"
    hotel_name: str
    passenger_name: str
    passenger_passport: str
    pnr: str
    # Injected synthetic canary data
    canary_id: str
    canary_token: str
    amount_minor_units: int
    currency: str
    created_at: float

class BookingPatchRequest(BaseModel):
    passenger_name: Optional[str] = None
    passenger_passport: Optional[str] = None

def get_session(authorization: Optional[str] = Header(None)) -> SessionContext:
    if not authorization or authorization not in TOKEN_MAP:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid synthetic Bearer token"
        )
    data = TOKEN_MAP[authorization]
    return SessionContext(**data)

class BaseTravelService:
    """Base in-memory state engine for the B2B travel simulator."""
    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.quotes: Dict[str, Quote] = {}
        self.holds: Dict[str, Hold] = {}
        self.bookings: Dict[str, Booking] = {}
        self._seed_default_quotes()

    def _seed_default_quotes(self) -> None:
        q1 = Quote(
            quote_id="QT_GOA_501",
            destination="Goa",
            hotel_name="Grand Hyatt Goa",
            room_type="Deluxe Ocean View",
            amount_minor_units=1800000, # 18,000 INR
            currency="INR",
            expires_at=time.time() + 1800
        )
        self.quotes[q1.quote_id] = q1

    def search(self, req: SearchRequest) -> List[Quote]:
        return list(self.quotes.values())

    def create_hold(self, session: SessionContext, req: HoldRequest) -> Hold:
        quote = self.quotes.get(req.quote_id)
        if not quote:
            raise HTTPException(status_code=404, detail="Quote not found")
        if time.time() > quote.expires_at:
            raise HTTPException(status_code=400, detail="Quote has expired")

        hold_token = f"HLD_{uuid.uuid4().hex[:8]}"
        hold = Hold(
            hold_token=hold_token,
            quote_id=quote.quote_id,
            tenant_id=session.tenant_id,
            status="HELD",
            expires_at=time.time() + 600
        )
        self.holds[hold_token] = hold
        return hold

    def create_booking(self, session: SessionContext, req: BookingRequest) -> Booking:
        raise NotImplementedError

    def get_booking(self, session: SessionContext, booking_id: str) -> Booking:
        raise NotImplementedError

    def modify_booking(self, session: SessionContext, booking_id: str, patch: BookingPatchRequest) -> Booking:
        raise NotImplementedError

def create_travel_app(service: BaseTravelService) -> FastAPI:
    """Application factory providing identical route contracts."""
    app = FastAPI(title="TBO Travel Simulator", version="2.0.0")

    @app.post("/api/v2/search")
    def search_endpoint(req: SearchRequest, session: SessionContext = Depends(get_session)):
        return service.search(req)

    @app.post("/api/v2/holds")
    def hold_endpoint(req: HoldRequest, session: SessionContext = Depends(get_session)):
        return service.create_hold(session, req)

    @app.post("/api/v2/bookings")
    def booking_endpoint(req: BookingRequest, session: SessionContext = Depends(get_session)):
        return service.create_booking(session, req)

    @app.get("/api/v2/bookings/{booking_id}")
    def get_booking_endpoint(booking_id: str, session: SessionContext = Depends(get_session)):
        return service.get_booking(session, booking_id)

    @app.patch("/api/v2/bookings/{booking_id}")
    def patch_booking_endpoint(booking_id: str, patch: BookingPatchRequest, session: SessionContext = Depends(get_session)):
        return service.modify_booking(session, booking_id, patch)

    @app.post("/api/v2/reset")
    def reset_endpoint():
        service.reset()
        return {"status": "RESET_SUCCESS", "timestamp": time.time()}

    return app
