from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Optional
from MobyPark.api.authentication import get_current_user, require_roles

from MobyPark.api import session_calculator as sc
from fastapi import Request
from MobyPark.api.Models import (
    Vehicle,
    Session,
    Payment,
    Reservation,
    ParkingLot,
    User,
    DiscountCodeResponse,
)

# Create router
router = APIRouter(tags=["get_routes"])

# Response Models


class BillingItem(BaseModel):
    session: dict
    parking: dict
    amount: float
    thash: str
    payed: float
    balance: float


class FreeParkingResponse(BaseModel):
    id: int
    license_plate: str
    added_by: int
    created_at: Optional[str] = None


@router.get("/profile", response_model=User)
async def get_profile(
    request: Request,
    user: User = Depends(get_current_user)
) -> User:
    """Get the profile of the currently authenticated user."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    return user


@router.get("/profile/{user_id}", response_model=User)
async def get_profile_by_id(
    request: Request,
    user_id: str,
    current_user: User = Depends(get_current_user)
) -> User:
    """Get profile by user ID (admin only or own profile)."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_users
    target_user = access_users.get_user_byid(id=user_id)
    
    if not target_user:
        Logger.error(f"User not found with ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if current_user.role != "ADMIN" and str(current_user.id) != str(user_id):
        Logger.error(f"Access denied: User {current_user.id} tried to access profile of user {user_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only view your own profile."
        )
    
    return target_user


@router.get("/parkinglots", response_model=List[ParkingLot])
async def get_parking_lots(
    request: Request,
    current_user: User = Depends(get_current_user)
    ):
    """Get all parking lots."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_parkinglots
    parking_lots = access_parkinglots.get_all_parking_lots()
    return parking_lots


@router.get("/parkinglots/{lid}", response_model=ParkingLot)
async def get_parking_lot_details(
    request: Request,
    lid: str,
    current_user: User = Depends(get_current_user)
) -> ParkingLot:
    """Get details of a specific parking lot."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_parkinglots
    parking_lot = access_parkinglots.get_parking_lot(id=lid)
    if not parking_lot:
        Logger.error(f"Parking lot not found with ID: {lid}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parking lot not found"
        )
    return parking_lot


@router.get("/reservations", response_model=List[Reservation])
async def get_reservations(
    request: Request,
    user: User = Depends(get_current_user)
) -> List[Reservation]:
    """Get all reservations (admin) or user's reservations."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_reservations
    if user.role == "ADMIN":
        return access_reservations.get_all_reservations()
    return access_reservations.get_reservations_by_user(user=user)


@router.get("/reservations/{rid}", response_model=Reservation)
async def get_reservation_details(
    request: Request,
    rid: str,
    user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get details of a specific reservation."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_reservations
    reservation = access_reservations.get_reservation(id=rid)
    if not reservation:
        Logger.error(f"Reservation not found with ID: {rid}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reservation not found"
        )
    
    if user.role != "ADMIN" and user.id != reservation.user.id:
        Logger.error(f"Access denied: User {user.id} tried to access reservation {rid} without permission")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return reservation


@router.get("/vehicles", response_model=List[Vehicle])
async def get_vehicles(
    request: Request,
    user: User = Depends(get_current_user)
) -> List[Vehicle]:
    """Get all vehicles (admin) or user's vehicles."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_vehicles
    if user.role == "ADMIN":
        return access_vehicles.get_all_vehicles()
    return access_vehicles.get_vehicles_byuser(user=user)


@router.get("/payments", response_model=List[Payment])
async def get_payments(
    request: Request,
    user: User = Depends(get_current_user)
) -> List[Payment]|List[dict]:
    """Get all payments (admin) or user's payments."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_payments
    if user.role == "ADMIN":
        return access_payments.get_all_payments()
    return access_payments.get_payments_by_user(user_id=user)


@router.get("/payments/{pid}", response_model=Payment)
async def get_payment_details(
    request: Request,
    pid: str,
    user: User = Depends(get_current_user)
) -> Payment:
    """Get details of a specific payment."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_payments
    payment = access_payments.get_payment(id=pid)
    if not payment:
        Logger.error(f"Payment not found with ID: {pid}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Payment not found"
        )
    
    if user.role != "ADMIN" and payment.user.id != user.id:
        Logger.error(f"Access denied: User {user.id} tried to access payment {pid} without permission")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return payment


@router.get("/billing", response_model=List[BillingItem])
async def get_billing(
    request: Request,
    user: User = Depends(get_current_user)
) -> List[BillingItem]:
    """Get billing information for the current user."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_sessions
    sessions = access_sessions.get_sessions_byuser(user=user)
    return _process_billing_sessions(sessions)


@router.get("/billing/{username}", response_model=List[BillingItem])
async def get_user_billing(
    request: Request,
    username: str,
    current_user: User = Depends(require_roles(["ADMIN"]))
) -> List[BillingItem]:
    """Get billing information for a specific user (admin only)."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_users
    from MobyPark.api.app import access_sessions
    target_user = access_users.get_user_byusername(username=username)
    if not target_user:
        Logger.error(f"User not found with username: {username}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    sessions = access_sessions.get_sessions_byuser(user=target_user)
    return _process_billing_sessions(sessions)


def _process_billing_sessions(sessions: List[Session]) -> List[BillingItem]:
    """Helper function to process sessions into billing items."""

    from MobyPark.api.app import access_payments
    billing_items = []
    for session in sessions:
        amount, hours, days = sc.calculate_price(session.parking_lot, session)
        transaction = sc.generate_payment_hash(session.id, session)
        payment = access_payments.get_payment_by_session(session)
        payed = payment.amount if payment is not None else 0.0
        
        billing_items.append(BillingItem(
            session = {
                "licenseplate": session.licenseplate,
                "started": session.started,
                "stopped": session.stopped,
                "hours": hours,
                "days": days
            },
            parking = {
                "name": session.parking_lot.name,
                "location": session.parking_lot.location,
                "tariff": session.parking_lot.tariff,
                "daytariff": session.parking_lot.daytariff
            },
            amount = amount,
            thash = transaction,
            payed = payed,
            balance = amount - payed
        ))
    return billing_items
    

@router.get("/discount-codes/free-parking", response_model=List[FreeParkingResponse])
async def list_free_parking_plates(
    request: Request,
    user: User = Depends(require_roles(["ADMIN"]))
):
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from ..app import access_free_parking
    try:
        plates = access_free_parking.get_all_free_parking_plates()
        return [
            {
                "id": plate.id,
                "license_plate": plate.license_plate,
                "added_by": plate.added_by,
                "created_at": plate.created_at.isoformat() if plate.created_at else None
            }
            for plate in plates
        ]
    except Exception as e:
        Logger.error(f"Error listing free parking plates: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/discount-codes", response_model=List[DiscountCodeResponse])
async def list_discount_codes(
    request: Request,
    user: User = Depends(require_roles(["ADMIN"]))
):
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_discount_codes
    try:
        codes = access_discount_codes.get_all_discount_codes()
        # Convert dictionary to DiscountCode objects if needed
        if codes and isinstance(codes[0], dict):
            return codes  # Already in the correct format for Pydantic
        return [code.to_dict() for code in codes]
    except Exception as e:
        Logger.error(f"Error listing discount codes: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve discount codes")


@router.get("/discount-codes/{code_id}", response_model=DiscountCodeResponse)
async def get_discount_code(
    request: Request,
    code_id: int,
    user: User = Depends(require_roles(["ADMIN"]))
):
    """
    Get a discount code by its ID
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_discount_codes
    try:
        code = access_discount_codes.get_discount_code_by_id(code_id)
        if not code:
            Logger.error(f"Discount code not found with ID: {code_id}")
            raise HTTPException(status_code=404, detail="Discount code not found")
            
        if hasattr(code, 'to_dict'):
            return code.to_dict()
        return code
        
    except HTTPException:
        raise
    except Exception as e:
        Logger.error(f"Error getting discount code {code_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve discount code")


@router.get("/feedback")
async def get_feedback(
    request: Request,
    lot_id: str,
    user: User = Depends(require_roles(["ADMIN"]))):
    """
    View feedback for a specific parking lot (Admin only).
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_feedback
    filtered_feedback = access_feedback.get_feedback_by_parkinglot_id(parkinglot_id=lot_id)

    return filtered_feedback
    

@router.get("/analytics/occupancy")
async def get_occupancy_analytics(
    request: Request,
    lot_id: str = Query(..., description="ID of the parking lot"),
    days: int = Query(30, description="Number of days to look back"),
    user: User = Depends(require_roles("ADMIN"))
):
    """
    Get occupancy analytics for a parking lot over time
    
    Returns a list of occupancy percentages for each day in the specified time range
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from ..app import access_analytics
    try:
        occupancy_data = access_analytics.get_occupancy_over_time(lot_id, days)
        return {
            "lot_id": lot_id,
            "time_period_days": days,
            "data": occupancy_data
        }
    except Exception as e:
        Logger.error(f"Error in get_occupancy_analytics: {str(e)}")
        # Return empty data instead of error for now
        return {
            "lot_id": lot_id,
            "time_period_days": days,
            "data": [{"date": (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d'), 
                     "occupancy_percentage": 0} 
                    for i in range(days, 0, -1)]
        }


@router.get("/analytics/revenue", response_model=dict)
async def get_revenue_analytics(
    request: Request,
    lot_id: str = Query(..., description="ID of the parking lot"),
    start_date: str = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: str = Query(None, description="End date (YYYY-MM-DD)"),
    user: User = Depends(require_roles("ADMIN"))
):
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from ..app import access_analytics
    try:
        revenue_data = access_analytics.get_revenue(lot_id, start_date, end_date)
        return {
            "lot_id": lot_id,
            "start_date": revenue_data["start_date"],
            "end_date": revenue_data["end_date"],
            "total_revenue": revenue_data["total_revenue"],
            "total_transactions": revenue_data["total_transactions"],
            "breakdown": revenue_data["breakdown"]
        }
    except Exception as e:
        #TODO: logger.error(f"Error in get_revenue_analytics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve revenue data: {str(e)}"
        )