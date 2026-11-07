"""Patched B2B travel service with enforced tenant boundaries and server-authoritative pricing."""

import time
import uuid
from fastapi import HTTPException, status
from tests.fixtures.mock_travel_api import (
    BaseTravelService,
    SessionContext,
    BookingRequest,
    Booking,
    BookingPatchRequest,
    create_travel_app
)

class PatchedTravelService(BaseTravelService):
    """
    Remediated service implementation:
    - I-01 Enforced: Multi-tenant ownership strictly verified against session context.
    - I-02 Enforced: Authoritative server quote determines pricing; client tampering is rejected.
    """
    def create_booking(self, session: SessionContext, req: BookingRequest) -> Booking:
        if req.hold_token:
            hold = self.holds.get(req.hold_token)
            if not hold:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hold token not found")

            # Invariant I-01 Guard: Verify hold belongs to the requesting tenant
            if hold.tenant_id != session.tenant_id and session.parent_tenant_id != hold.tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Hold token belongs to another agency"
                )

            if time.time() > hold.expires_at:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Hold has expired")
        else:
            # Auto-provision valid hold for session tenant
            hold = self.create_hold(session, type("AutoHoldRequest", (), {"quote_id": "QT_GOA_501"})())
            if not hold:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Could not auto-provision hold")

        quote = self.quotes.get(hold.quote_id)
        if not quote:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Underlying quote not found")

        # Invariant I-02 Guard: Authoritative Server Pricing
        # If client sends tampered amount or currency, reject with 400 Bad Request
        if req.client_amount_minor_units is not None:
            if req.client_amount_minor_units != quote.amount_minor_units:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Price tampering detected: submitted {req.client_amount_minor_units} != quote {quote.amount_minor_units}"
                )

        if req.client_currency is not None:
            if req.client_currency != quote.currency:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Currency tampering detected: submitted {req.client_currency} != quote {quote.currency}"
                )

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
            amount_minor_units=quote.amount_minor_units, # Server-authoritative
            currency=quote.currency,
            created_at=time.time()
        )
        self.bookings[booking_id] = booking
        return booking

    def get_booking(self, session: SessionContext, booking_id: str) -> Booking:
        booking = self.bookings.get(booking_id)
        if not booking:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

        # Invariant I-01 Guard: Strict Tenant Authorization Check
        if booking.owner_tenant_id != session.tenant_id and session.parent_tenant_id != booking.owner_tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access Denied: Booking object belongs to another agency"
            )

        return booking

    def modify_booking(self, session: SessionContext, booking_id: str, patch: BookingPatchRequest) -> Booking:
        booking = self.bookings.get(booking_id)
        if not booking:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Booking not found")

        # Invariant I-01 Guard: Strict Tenant Authorization Check on Mutations
        if booking.owner_tenant_id != session.tenant_id and session.parent_tenant_id != booking.owner_tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access Denied: Cannot modify booking belonging to another agency"
            )

        if patch.passenger_name:
            booking.passenger_name = patch.passenger_name
        if patch.passenger_passport:
            booking.passenger_passport = patch.passenger_passport
        return booking

def create_patched_app():
    return create_travel_app(PatchedTravelService())
