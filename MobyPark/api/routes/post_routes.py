from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from fastapi import Request
import uuid
import re
import hashlib
import bcrypt
import os

from .. import session_manager, session_calculator
from ..authentication import get_current_user, require_roles
from MobyPark.api.DataAccess import Logger
from MobyPark.api.Models import (
    Vehicle,
    Session,
    Payment,
    Feedback,
    TransactionData,
    Reservation,
    ParkingLot,
    ParkingLotCoordinates,
    User,
    DiscountCodeResponse,
    generate_discount_code,
    DiscountCodeCreate,
    ApplyDiscountRequest,
    ApplyDiscountResponse)

# Create router
router = APIRouter(tags=["post_routes"])

# ============================================
# Request/Response Models
# ============================================

class RegisterRequest(BaseModel):
    username: str
    password: str
    name: str
    phone: str
    email: EmailStr
    birth_year: int
    role: str = "USER"

class ParkingLotCreate(BaseModel):
    name: str
    location: str
    capacity: int
    tariff: float
    daytariff: float
    address: str
    coordinates: ParkingLotCoordinates

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    message: str
    session_token: str

class SessionRequest(BaseModel):
    license_plate: str = None
    licenseplate: str = None

class PaymentCreate(BaseModel):
    transaction: str
    amount: float
    session_id: int
    t_data: TransactionData

class RefundCreate(BaseModel):
    amount: float
    session_id: int
    t_data: TransactionData
    transaction: Optional[str] = None
    coupled_to: Optional[str] = None

class ReservationCreate(BaseModel):
    parkinglot: str
    user: Optional[str] = None
    start_time: str
    end_time: str
    license_plate: Optional[str] = None
    licenseplate: Optional[str] = None


class FreeParkingResponse(BaseModel):
    id: int
    license_plate: str
    added_by: int
    created_at: Optional[str] = None


class FreeParkingRequest(BaseModel):
    license_plate: str


class CreateFeedback(BaseModel):
    lot_id: str
    rating: int
    comment: Optional[str] = None

# ============================================
# Helper Functions
# ============================================

def validate_license_plate(license_plate: str) -> str:
    """Helper to handle both license_plate and licenseplate fields."""
    lp = license_plate
    if not lp or not isinstance(lp, str) or not lp.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="License plate is required"
        )
    return lp

def _parse_dt(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid datetime format (expected YYYY-MM-DD HH:MM:SS)"
        )

# ============================================
# Authentication Routes
# ============================================

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    register_data: RegisterRequest,
    request: Request
    ):
    """Register a new user (admin only)."""
    from MobyPark.api.app import access_users
    # Check if username already exists
    if access_users.get_user_byusername(username=register_data.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken"
        )
    
    # Hash password
    TEST_MODE = os.environ.get('TEST_MODE') == '1'
    if TEST_MODE:
        # In tests, use faster hashing
        hashed_password = hashlib.sha256(register_data.password.encode('utf-8')).hexdigest()
    else:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(register_data.password.encode('utf-8'), salt).decode('utf-8')

    # Create new user
    new_user = User(
        username=register_data.username,
        password=hashed_password,
        name=register_data.name,
        phone=register_data.phone,
        email=register_data.email,
        birth_year=register_data.birth_year,
        role=register_data.role,
        active=True,
        created_at=datetime.now().replace(microsecond=0)
    )
    
    # Save user to database
    access_users.add_user(user=new_user)
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(new_user, endpoint)
    return {"message": "User created"}

# ============================================
# Login Route
# ============================================

@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    ):
    """Authenticate user and return session token."""
    from MobyPark.api.app import access_users
    user = access_users.get_user_byusername(username=login_data.username)

    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Check password
    if user.password.startswith("$2b$"):
        # Bcrypt hash
        if not bcrypt.checkpw(login_data.password.encode('utf-8'), user.password.encode('utf-8')):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
    else:
        # Legacy SHA256 hash (for testing)
        hashed_input = hashlib.sha256(login_data.password.encode('utf-8')).hexdigest()
        if hashed_input != user.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
    
    # Create session
    token = str(uuid.uuid4())
    session_manager.add_session(token, user)
    
    return {
        "message": "User logged in",
        "session_token": token
    }

# ============================================
# Logout Route
# ============================================

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Invalidate the current session."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    auth_header = request.headers.get("Authorization")
    if auth_header:
        token = auth_header.split(" ")[1] if " " in auth_header else auth_header
        session_manager.remove_session(token)
    
    return {"message": "User logged out successfully"}

# ============================================
# Parking Lot Routes
# ============================================

@router.post("/parkinglots", status_code=status.HTTP_201_CREATED)
async def create_parking_lot(
    parking_data: ParkingLotCreate,
    request: Request,
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    """Create a new parking lot (admin only)."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_parkinglots
    parking_lot = ParkingLot(
        id = None,
        name = parking_data.name,
        location = parking_data.location,
        address = parking_data.address,
        capacity = parking_data.capacity,
        reserved = 0,
        tariff = parking_data.tariff,
        daytariff = parking_data.daytariff,
        coordinates = parking_data.coordinates,
        created_at = datetime.now().replace(microsecond=0)
    )
    access_parkinglots.add_parking_lot(parkinglot=parking_lot)
    
    return {"Server message": f"Parking lot saved under ID: {parking_lot.id}"}

# Reservation Routes
# ============================================

@router.post("/reservations", status_code=status.HTTP_201_CREATED)
async def create_reservation(
    request: Request,
    reservation_data: ReservationCreate,
    current_user: User = Depends(get_current_user)
):
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_reservations, access_parkinglots, access_users, access_vehicles

    target_username = reservation_data.user or current_user.username
    if current_user.role != "ADMIN" and target_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    target_user = access_users.get_user_byusername(username=target_username)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    parking_lot = access_parkinglots.get_parking_lot(id=reservation_data.parkinglot)
    if not parking_lot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")

    lp = reservation_data.license_plate or reservation_data.licenseplate
    lp = validate_license_plate(lp)
    vehicle = access_vehicles.get_vehicle_bylicenseplate(licenseplate=lp)
    if not vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found")

    start_dt = _parse_dt(reservation_data.start_time)
    end_dt = _parse_dt(reservation_data.end_time)
    if end_dt <= start_dt:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="End time must be after start time")

    reservation = Reservation(
        user=target_user,
        parking_lot=parking_lot,
        vehicle=vehicle,
        start_time=start_dt,
        end_time=end_dt,
        status="CREATED",
        created_at=datetime.now().replace(microsecond=0),
        cost=0.0,
        id=None,
    )
    access_reservations.add_reservation(reservation=reservation)

    parking_lot.reserved = (parking_lot.reserved or 0) + 1
    access_parkinglots.update_parking_lot(parkinglot=parking_lot)
    return {"status": "Created", "reservation": reservation.dict()}

# ============================================
# Session Routes
# ============================================

@router.post("/parkinglots/{lid}/sessions/start")
async def start_session(
    lid: str,
    session_data: SessionRequest,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Start a new parking session."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_sessions
    from MobyPark.api.app import access_parkinglots
    # Get parking lot
    parking_lot = access_parkinglots.get_parking_lot(id=lid)
    if not parking_lot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parking lot not found"
        )
    
    # Validate license plate
    license_plate = validate_license_plate(
        session_data.license_plate or session_data.licenseplate
    )
    
    # Create session
    session = Session(
        parking_lot=parking_lot,
        user=current_user,
        licenseplate=license_plate,
        started=datetime.now().replace(microsecond=0),
        duration_minutes=None,
        cost=0.0,
        payment_status="pending",
        username=current_user.username
    )
    
    # Add session to database
    if access_sessions.get_pending_session_bylicenseplate(licenseplate=license_plate):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot start a session when another session for this license plate is already started."
        )

    access_sessions.add_session(session=session)

    return {"Server message": f"Session started for: {license_plate} under id: {session.id}"}


@router.post("/parkinglots/{lid}/sessions/stop")
async def stop_session(
    lid: str,
    session_data: SessionRequest,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Stop an active parking session."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_sessions
    from MobyPark.api.app import access_parkinglots
    # Get parking lot
    parking_lot = access_parkinglots.get_parking_lot(id=lid)
    if not parking_lot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parking lot not found"
        )
    
    # Validate license plate
    license_plate = validate_license_plate(
        session_data.license_plate or session_data.licenseplate
    )
    
    # Get active session
    session = access_sessions.get_pending_session_bylicenseplate(licenseplate=license_plate)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot stop a session when there is no active session for this license plate."
        )
    
    # Update session
    session.stopped = datetime.now().replace(microsecond=0)
    access_sessions.update_session(session=session)
    
    return {"Server message": f"Session stopped for: {license_plate}"}

# ============================================
# Vehicle Routes
# ============================================

@router.post("/vehicles", status_code=status.HTTP_201_CREATED)
async def create_vehicle(
    vehicle_data: Vehicle,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Register a new vehicle for the current user."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_vehicles
    # Check if vehicle already exists
    if access_vehicles.get_vehicle_bylicenseplate(licenseplate=vehicle_data.licenseplate):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vehicle with this license plate already exists"
        )
    
    # Create vehicle
    vehicle = Vehicle(
        user=current_user,
        licenseplate=vehicle_data.licenseplate,
        make=vehicle_data.make,
        model=vehicle_data.model,
        color=vehicle_data.color,
        year=vehicle_data.year,
        created_at=datetime.now().replace(microsecond=0)
    )
    
    # Save vehicle
    access_vehicles.add_vehicle(vehicle=vehicle)
    
    return {
        "status": "Success",
        "vehicle": {
            "id": vehicle.id,
            "license_plate": vehicle.licenseplate,
            "make": vehicle.make,
            "model": vehicle.model,
            "color": vehicle.color,
            "year": vehicle.year
        }
    }

# ============================================
# Payment Routes
# ============================================

@router.post("/payments", status_code=status.HTTP_201_CREATED)
async def create_payment(
    payment_data: PaymentCreate,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Create a new payment."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_payments, access_sessions
    session = access_sessions.get_session(id=payment_data.session_id)

    # Create payment
    payment = Payment(
        id=payment_data.transaction,
        user=current_user,
        amount=payment_data.amount,
        initiator=current_user.username,
        created_at=datetime.now().replace(microsecond=0),
        completed=None,
        session=session,
        parking_lot=session.parking_lot,
        t_data=payment_data.t_data,
        hash=session_calculator.generate_transaction_validation_hash()
    )
    
    # Save payment
    access_payments.add_payment(payment=payment)
    
    return {
        "status": "Success",
        "payment": {
            "transaction": payment.id,
            "amount": payment.amount,
            "initiator": payment.initiator,
            "created_at": payment.created_at,
            "completed": payment.completed
        }
    }

@router.post("/payments/refund", status_code=status.HTTP_201_CREATED)
async def refund_payment(
    refund_data: RefundCreate,
    request: Request,
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    """Create a refund payment (admin only)."""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)

    from MobyPark.api.app import access_payments, access_sessions
    # Generate transaction ID if not provided
    transaction_id = refund_data.transaction or str(uuid.uuid4())
    session = access_sessions.get_session(id=refund_data.session_id)
    
    # Create refund payment
    refund = Payment(
        id=transaction_id,
        amount=-abs(refund_data.amount),  # Negative amount for refund
        initiator=current_user.username,
        user=current_user,
        created_at=datetime.now().replace(microsecond=0),
        completed=None,
        session=session,
        parking_lot=session.parking_lot,
        hash=session_calculator.generate_transaction_validation_hash(),
        t_data=refund_data.t_data
    )
    
    # Save refund
    access_payments.add_payment(payment=refund)
    
    return {
        "status": "Success",
        "refund": {
            "transaction": refund.id,
            "amount": refund.amount,
            "initiator": refund.initiator,
            "coupled_to": refund_data.coupled_to,
            "created_at": refund.created_at
        }
    }


@router.post("/discount-codes/free-parking", response_model=FreeParkingResponse, status_code=201)
async def add_free_parking_plate(
    request_path: Request,
    request: FreeParkingRequest,
    user: User = Depends(require_roles("ADMIN"))
):
    from MobyPark.api.app import Logger
    endpoint = f"{request_path.method} {request_path.url.path}"
    Logger.log(user, endpoint)

    from ..app import access_free_parking
    try:
        free_parking = access_free_parking.add_free_parking_plate(
            license_plate=request.license_plate,
            added_by=user
        )
        
        return {
            "id": free_parking.id,
            "license_plate": free_parking.license_plate,
            "added_by": free_parking.added_by,
            "created_at": free_parking.created_at.isoformat() if free_parking.created_at else None
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # logger.log(f"Error adding free parking plate: {str(e)}")
        
        raise HTTPException(status_code=500, detail="Internal server error")
    

@router.post("/discount-codes", response_model=DiscountCodeResponse, status_code=201)
async def create_discount_code(
    request: Request,
    code_data: DiscountCodeCreate,
    user: User = Depends(require_roles("ADMIN"))
):
    """Create a new discount code with optional location and time rules"""
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_discount_codes
    try:
        code = code_data.code if code_data.code else generate_discount_code()
        
        discount_data = {
            'code': code,
            'discount_percentage': code_data.discount_percentage,
            'max_uses': code_data.max_uses,
            'valid_from': code_data.valid_from.isoformat() if code_data.valid_from else None,
            'valid_until': code_data.valid_until.isoformat() if code_data.valid_until else None,
            'created_by': user.id,
            'is_active': True,
            'location_rules': code_data.location_rules,
            'time_rules': code_data.time_rules
        }
        
        created_code = access_discount_codes.create_discount_code(discount_data)
        
        if hasattr(created_code, 'to_dict'):
            return created_code.to_dict()
        return created_code
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        #TODO: logger.log(f"Error creating discount code: {str(e)}", level="error")
        raise HTTPException(status_code=500, detail="Failed to create discount code")


@router.post("/payments/apply-discount", response_model=ApplyDiscountResponse)
async def apply_discount_code(
    request: ApplyDiscountRequest,
    user: User = Depends(get_current_user)
):
    from MobyPark.api.app import access_discount_codes, access_free_parking, access_vehicles
    if not request.code:
        return ApplyDiscountResponse(
            success=False,
            discount_amount=0,
            final_amount=request.amount,
            message="No discount code provided"
        )
    
    try:
        if request.code.upper() == "GRATIS":
            vehicles = access_vehicles.get_vehicles_by_user_id(user.id)
            for vehicle in vehicles:
                if access_free_parking.is_plate_free_parking(vehicle.licenseplate):
                    return ApplyDiscountResponse(
                        success=True,
                        discount_amount=request.amount,
                        final_amount=0,
                        message="100% discount applied (GRATIS)"
                    )
            
            return ApplyDiscountResponse(
                success=False,
                discount_amount=0,
                final_amount=request.amount,
                message="GRATIS code is only available for vehicles with free parking privileges"
            )
        
        final_amount, message = access_discount_codes.apply_discount_code(
            request.code, 
            user.id, 
            request.amount
        )
        
        discount_amount = request.amount - final_amount
        
        return ApplyDiscountResponse(
            success=True,
            discount_amount=discount_amount,
            final_amount=final_amount,
            message=message or f"Discount applied"
        )
        
    except ValueError as e:
        return ApplyDiscountResponse(
            success=False,
            discount_amount=0,
            final_amount=request.amount,
            message=str(e)
        )
    except Exception as e:
        #TODO: logger.log(f"Error applying discount code: {str(e)}", level="error")
        return ApplyDiscountResponse(
            success=False,
            discount_amount=0,
            final_amount=request.amount,
            message="Failed to apply discount code"
        )


@router.post("/feedback", status_code=status.HTTP_201_CREATED)
async def create_feedback(
    request: Request,
    body: CreateFeedback,
    user: User = Depends(get_current_user)):
    """
    Submit feedback for a specific parking lot.
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(user, endpoint)

    from MobyPark.api.app import access_feedback, access_parkinglots
    parking_lot = access_parkinglots.get_parking_lot(body.lot_id)
    if not parking_lot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Parking lot not found"
        )

    new_feedback = Feedback(
        user_id = user.id,
        lot_id = body.lot_id,
        rating = body.rating,
        comment = body.comment,
        created_at = datetime.now().replace(microsecond=0)
    )
    access_feedback.add_feedback(feedback=new_feedback)

    return {"message": "Feedback submitted successfully", "feedback": new_feedback}


# ============================================
# Admin Routes
# ============================================

@router.post("/debug/reset")
async def debug_reset(
    request: Request,
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    """
    Reset all data (admin only).
    WARNING: This will delete all data in the database!
    """
    from MobyPark.api.app import Logger
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)
    
    from MobyPark.api.app import connection
    # Truncate all tables
    connection.cursor.execute(
        "TRUNCATE TABLE users, parking_lots, reservations, payments, t_data, vehicles, sessions"
    )
    
    return {"Server message": "All data reset successfully"}