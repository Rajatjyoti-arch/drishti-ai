"""Vulnerable B2B travel service with deliberate I-01 (BOLA) and I-02 (Pricing) flaws."""

import time
import uuid
from fastapi import HTTPException
from tests.fixtures.mock_travel_api import (
    BaseTravelService,
    SessionContext,
    BookingRequest,
    Booking,
    BookingPatchRequest,
    create_travel_app
)

class VulnerableTravelService(BaseTravelService):
    """
    Deliberately flawed service implementation:
    - I-01: No tenant ownership check on booking retrieval and modification (BOLA/IDOR).
    - I-02: Trusts client-controlled price and currency parameters on checkout.
    """
    def create_booking(self, session: SessionContext, req: BookingRequest) -> Booking:
        if req.hold_token:
            hold = self.holds.get(req.hold_token)
            if not hold:
                raise HTTPException(status_code=404, detail="Hold token not found")
        else:
            # Auto-provision hold for fixture setup
            hold_token = f"HLD_AUTO_{uuid.uuid4().hex[:8]}"
            hold = self.create_hold(session, type("AutoHoldRequest", (), {"quote_id": "QT_GOA_501"})())
            if not hold:
                raise HTTPException(status_code=404, detail="Could not auto-provision hold")

        quote = self.quotes.get(hold.quote_id)
        if not quote:
            raise HTTPException(status_code=404, detail="Underlying quote not found")

        # Flaw I-02: Client Price & Currency Tampering Accepted!
        # If the client specifies amount or currency, the server trusts it blindly
        final_amount = req.client_amount_minor_units if req.client_amount_minor_units is not None else quote.amount_minor_units
        final_currency = req.client_currency if req.client_currency is not None else quote.currency

        booking_id = f"TBOH_{uuid.uuid4().hex[:8]}"
        canary_token = f"CANARY_{uuid.uuid4().hex[:12]}"
        
        booking = Booking(
            booking_id=booking_id,
            hold_token=hold.hold_token,
            owner_tenant_id=session.tenant_id,
            status="CONFIRMED",
            hotel_name=quote.hotel_name,
            passenger_name=req.passenger_name,
            passenger_passport=req.passenger_passport or "P1234567",
            pnr=f"PNR_{uuid.uuid4().hex[:6].upper()}",
            canary_id=f"canary_for_{session.tenant_id}",
            canary_token=canary_token,
            amount_minor_units=final_amount,
            currency=final_currency,
            created_at=time.time()
        )
        self.bookings[booking_id] = booking
        return booking

    def get_booking(self, session: SessionContext, booking_id: str) -> Booking:
        booking = self.bookings.get(booking_id)
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")

        # Flaw I-01: Missing Ownership Check (BOLA / IDOR)!
        # Returns Agency A's booking (and private canary/PII) to Agency B without error
        return booking

    def modify_booking(self, session: SessionContext, booking_id: str, patch: BookingPatchRequest) -> Booking:
        booking = self.bookings.get(booking_id)
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")

        # Flaw I-01: Unauthorized Mutation Accepted without checking owner_tenant_id!
        if patch.passenger_name:
            booking.passenger_name = patch.passenger_name
        if patch.passenger_passport:
            booking.passenger_passport = patch.passenger_passport
        return booking

def create_vulnerable_app():
    return create_travel_app(VulnerableTravelService())
