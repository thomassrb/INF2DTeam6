from typing import Dict, Any, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Path, Body
from pydantic import BaseModel
from fastapi import Request

from MobyPark.api.authentication import get_current_user, require_roles
from MobyPark.api.Models import (
    User,
    DiscountCodeResponse
    )
from MobyPark.api.authentication import PasswordManager
from MobyPark.api.DataAccess import Logger

# Initialize router
router = APIRouter(tags=["put_routes"])

password_manager = PasswordManager()

# Request models
class ParkingLotUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    capacity: Optional[int] = None
    tariff: Optional[float] = None
    daytariff: Optional[float] = None
    address: Optional[str] = None
    coordinates: Optional[list[float]] = None

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None

class ReservationUpdate(BaseModel):
    parkinglot: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    license_plate: Optional[str] = None
    licenseplate: Optional[str] = None
    user: Optional[str] = None

class VehicleUpdate(BaseModel):
    name: Optional[str] = None
    licenseplate: Optional[str] = None

class PaymentUpdate(BaseModel):
    validation: str
    t_data: Dict[str, Any]

# Routes
@router.put("/parkinglots/{lid}")
async def update_parking_lot(
    request: Request,
    lid: str = Path(..., description="The ID of the parking lot to update"),
    update_data: ParkingLotUpdate = Body(...),
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    """
    Update a parking lot's information. Admin only.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    try:
        from MobyPark.api.app import access_parkinglots
        parking_lot = access_parkinglots.get_parking_lot(id=lid)
        
        if not parking_lot:
            Logger.error(f"Parking lot not found with ID: {lid}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parking lot not found"
            )
        
        # Update only provided fields
        update_data_dict = update_data.dict(exclude_unset=True)
        for key, value in update_data_dict.items():
            if hasattr(parking_lot, key):
                setattr(parking_lot, key, value)
        
        access_parkinglots.update_parking_lot(parkinglot=parking_lot)
        # TODO: Add audit logging
        
        return {"message": "Parking lot updated successfully"}
    except Exception as e:
        Logger.error(f"Error updating parking lot: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update parking lot")
        

@router.put("/profile/{user_id}")
async def update_profile_by_id(
    request: Request,
    user_id: str = Path(..., description="The ID of the user to update"),
    update_data: ProfileUpdate = Body(...),
    current_user: User = Depends(get_current_user)
):
    """
    Update a user's profile. Users can update their own profile, admins can update any profile.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    try:
        from MobyPark.api.app import access_users
        target_user = access_users.get_user_byid(id=user_id)
        
        if not target_user:
            Logger.error(f"User not found with ID: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check permissions
        is_admin = current_user.role == "ADMIN"
        if not is_admin and current_user.id != user_id:
            Logger.error(f"Unauthorized profile update attempt by user {current_user.id} for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only update your own profile."
            )
        
        # Update only provided fields
        update_data_dict = update_data.dict(exclude_unset=True)
        
        # Hash password if provided
        if 'password' in update_data_dict and update_data_dict['password']:
            update_data_dict['password'] = password_manager.hash_password(update_data_dict['password'])
        
        for key, value in update_data_dict.items():
            if hasattr(target_user, key):
                setattr(target_user, key, value)
        
        access_users.update_user(user=target_user)
        # TODO: Add audit logging
        
        return {"message": "User updated successfully"}
    except Exception as e:
        Logger.error(f"Error updating user profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update user profile")


@router.put("/reservations/{reservation_id}")
async def update_reservation(
    request: Request,
    reservation_id: str = Path(..., description="The ID of the reservation to update"),
    update_data: ReservationUpdate = Body(...),
    current_user: User = Depends(get_current_user)
):
    """
    Update a reservation. Users can update their own reservations, admins can update any reservation.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    try:
        from MobyPark.api.app import access_reservations
        reservation = access_reservations.get_reservation(id=reservation_id)
        
        if not reservation:
            Logger.error(f"Reservation not found with ID: {reservation_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reservation not found"
            )
        
        # Check permissions
        is_admin = current_user.role == "ADMIN"
        if not is_admin and reservation.user != current_user.username:
            Logger.error(f"Unauthorized reservation update attempt by user {current_user.id} for reservation {reservation_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only update your own reservations."
            )
        
        # Update only provided fields
        update_data_dict = update_data.dict(exclude_unset=True)
        
        # For non-admin users, ensure they can't change the user field
        if not is_admin and 'user' in update_data_dict and update_data_dict['user'] != current_user.username:
            Logger.error(f"User {current_user.id} attempted to change user field in reservation {reservation_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update your own reservations."
            )
        
        for key, value in update_data_dict.items():
            if hasattr(reservation, key):
                setattr(reservation, key, value)
        
        access_reservations.update_reservation(reservation=reservation)
        # TODO: Add audit logging
        
        return {"status": "Updated", "reservation": update_data_dict}
    except Exception as e:
        Logger.error(f"Error updating reservation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update reservation")


@router.put("/vehicles/{vehicle_id}")
async def update_vehicle(
    request: Request,
    vehicle_id: str = Path(..., description="The ID of the vehicle to update"),
    update_data: VehicleUpdate = Body(...),
    current_user: User = Depends(get_current_user)
):
    """
    Update a vehicle. Users can update their own vehicles.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    try:
        from MobyPark.api.app import access_vehicles
        vehicle = access_vehicles.get_vehicle(id=vehicle_id)
        
        if not vehicle:
            Logger.error(f"Vehicle not found with ID: {vehicle_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vehicle not found"
            )
        
        # Check if the current user owns the vehicle
        if vehicle.user != current_user.id and current_user.role != "ADMIN":
            Logger.error(f"Unauthorized vehicle update attempt by user {current_user.id} for vehicle {vehicle_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only update your own vehicles."
            )
        
        # Update only provided fields
        update_data_dict = update_data.dict(exclude_unset=True)
        
        for key, value in update_data_dict.items():
            if hasattr(vehicle, key):
                setattr(vehicle, key, value)
        
        access_vehicles.update_vehicle(vehicle=vehicle)
        # TODO: Add audit logging
        
        return {"status": "Success", "vehicle_id": vehicle_id}
    except Exception as e:
        Logger.error(f"Error updating vehicle: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update vehicle")


@router.put("/payments/{payment_id}")
async def update_payment(
    request: Request,
    payment_id: str = Path(..., description="The ID of the payment to update"),
    update_data: PaymentUpdate = Body(...),
    current_user: User = Depends(get_current_user)
):
    """
    Update a payment. This is typically used to mark a payment as completed.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)
    
    try:
        from MobyPark.api.app import access_payments
        payment = access_payments.get_payment(id=payment_id)
        
        if not payment:
            Logger.error(f"Payment not found with ID: {payment_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Payment not found"
            )
        
        # Validate the payment hash
        if payment.hash != update_data.validation:
            Logger.error(f"Payment validation failed for payment ID: {payment_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "Validation failed",
                    "info": "The validation of the security hash could not be validated for this transaction."
                }
            )
        
        # Update transaction data
        for key, value in update_data.t_data.items():
            if hasattr(payment.t_data, key):
                setattr(payment.t_data, key, value)
        
        # Mark as completed
        payment.completed = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        
        access_payments.update_payment(payment=payment)
        # TODO: Add audit logging
        
        return {"status": "Success", "payment_id": payment_id}
    except Exception as e:
        Logger.error(f"Error updating payment: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update payment")


@router.put("/discount-codes/{code_id}", response_model=DiscountCodeResponse)
async def update_discount_code(
    request: Request,
    code_id: int,
    code_data: dict,
    user: User = Depends(require_roles("ADMIN"))
):
    """Update a discount code"""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_discount_codes
    try:
        # Get existing code
        existing_code = access_discount_codes.get_discount_code_by_id(code_id)
        if not existing_code:
            raise HTTPException(status_code=404, detail="Discount code not found")
        
        # Convert to dict if needed
        if hasattr(existing_code, 'to_dict'):
            existing_code = existing_code.to_dict()
        
        # Prepare updates
        updates = {}
        for field in ['code', 'discount_percentage', 'max_uses', 'valid_from', 
                     'valid_until', 'is_active', 'location_rules', 'time_rules']:
            if field in code_data and code_data[field] is not None:
                updates[field] = code_data[field]
        
        if not updates:
            return existing_code
        
        # Update the code
        updated_code = access_discount_codes.update_discount_code(code_id, **updates)
        if not updated_code:
            raise HTTPException(status_code=500, detail="Failed to update discount code")
            
        # Return the updated code
        if hasattr(updated_code, 'to_dict'):
            return updated_code.to_dict()
        return updated_code
        
    except HTTPException:
        raise
    except Exception as e:
        Logger.error(f"Error updating discount code: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update discount code")


