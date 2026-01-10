from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from datetime import datetime

from MobyPark.api.authentication import get_current_user, require_roles

from MobyPark.api import session_calculator as sc
from MobyPark.api.Models.User import User
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.Reservation import Reservation
from MobyPark.api.Models.Payment import Payment
from MobyPark.api.Models.Session import Session

# Create router
router = APIRouter()

# Response Models
class ProfileResponse(BaseModel):
    username: str
    role: str
    name: str
    email: str
    phone: str
    birth_year: int  # Changed from str to int to match User model
    created_at: str

class BillingItem(BaseModel):
    session: Dict[str, Any]
    parking: Dict[str, Any]
    amount: float
    thash: str
    payed: float
    balance: float

@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    user: User = Depends(get_current_user)
) -> ProfileResponse:
    """Get the profile of the currently authenticated user."""
    return ProfileResponse(
        username=user.username,
        role=user.role,
        name=user.name,
        email=user.email,
        phone=user.phone,
        birth_year=user.birth_year,
        created_at=user.created_at.strftime("%d-%m-%Y")
    )

@router.get("/profile/{user_id}", response_model=ProfileResponse)
async def get_profile_by_id(
    user_id: str,
    current_user: User = Depends(get_current_user)
) -> ProfileResponse:
    """Get profile by user ID (admin only or own profile)."""
    from MobyPark.api.app import access_users
    target_user = access_users.get_user_byid(id=user_id)
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if current_user.role != "ADMIN" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only view your own profile."
        )
    
    return ProfileResponse(
        username=target_user.username,
        role=target_user.role,
        name=target_user.name,
        email=target_user.email,
        phone=target_user.phone,
        birth_year=target_user.birth_year,
        created_at=target_user.created_at.strftime("%d-%m-%Y")
    )

@router.get("/parkinglots", response_model=List[Dict[str, Any]])
async def get_parking_lots():
    """Get all parking lots."""
    from MobyPark.api.app import access_parkinglots
    return access_parkinglots.get_all_parking_lots()

@router.get("/parkinglots/{lid}", response_model=Dict[str, Any])
async def get_parking_lot_details(
    lid: str
) -> Dict[str, Any]:
    """Get details of a specific parking lot."""
    from MobyPark.api.app import access_parkinglots
    parking_lot = access_parkinglots.get_parking_lot(id=lid)
    if not parking_lot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parking lot not found"
        )
    return parking_lot

@router.get("/reservations", response_model=List[Dict[str, Any]])
async def get_reservations(
    user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get all reservations (admin) or user's reservations."""
    from MobyPark.api.app import access_reservations
    if user.role == "ADMIN":
        return access_reservations.get_all_reservations()
    return access_reservations.get_reservations_by_user(user=user)

@router.get("/reservations/{rid}", response_model=Dict[str, Any])
async def get_reservation_details(
    rid: str,
    user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get details of a specific reservation."""
    from MobyPark.api.app import access_reservations
    reservation = access_reservations.get_reservation(id=rid)
    if not reservation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reservation not found"
        )
    
    if user.role != "ADMIN" and user.id != reservation.user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return reservation

@router.get("/vehicles", response_model=List[Dict[str, Any]])
async def get_vehicles(
    user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get all vehicles (admin) or user's vehicles."""
    from MobyPark.api.app import access_vehicles
    if user.role == "ADMIN":
        return access_vehicles.get_all_vehicles()
    return access_vehicles.get_vehicles_byuser(user=user)

@router.get("/payments", response_model=List[Dict[str, Any]])
async def get_payments(
    user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get all payments (admin) or user's payments."""
    from MobyPark.api.app import access_payments
    if user.role == "ADMIN":
        return access_payments.get_all_payments()
    return access_payments.get_payments_by_user(user_id=user)

@router.get("/payments/{pid}", response_model=Dict[str, Any])
async def get_payment_details(
    pid: str,
    user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get details of a specific payment."""
    from MobyPark.api.app import access_payments
    payment = access_payments.get_payment(id=pid)
    if not payment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Payment not found"
        )
    
    if user.role != "ADMIN" and payment.user.id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return payment

@router.get("/billing", response_model=List[BillingItem])
async def get_billing(
    user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get billing information for the current user."""
    from MobyPark.api.app import access_sessions
    sessions = access_sessions.get_sessions_byuser(user=user)
    return _process_billing_sessions(sessions)

@router.get("/billing/{username}", response_model=List[BillingItem])
async def get_user_billing(
    username: str,
    current_user: User = Depends(require_roles("ADMIN"))
) -> List[Dict[str, Any]]:
    """Get billing information for a specific user (admin only)."""
    from MobyPark.api.app import access_users
    from MobyPark.api.app import access_sessions
    target_user = access_users.get_user_by_username(username=username)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    sessions = access_sessions.get_sessions_byuser(user=target_user)
    return _process_billing_sessions(sessions)

def _process_billing_sessions(sessions: List[Session]) -> List[Dict[str, Any]]:
    """Helper function to process sessions into billing items."""
    billing_items = []
    for session in sessions:
        amount, hours, days = sc.calculate_price(session.parking_lot, session)
        transaction = sc.generate_payment_hash(session.id, session)
        payed = sc.check_payment_amount(transaction)
        
        billing_items.append({
            "session": {
                "licenseplate": session.licenseplate,
                "started": session.started,
                "stopped": session.stopped,
                "hours": hours,
                "days": days
            },
            "parking": {
                "name": session.parking_lot.name,
                "location": session.parking_lot.location,
                "tariff": session.parking_lot.tariff,
                "daytariff": session.parking_lot.daytariff
            },
            "amount": amount,
            "thash": transaction,
            "payed": payed,
            "balance": amount - payed
        })
    return billing_items
    
