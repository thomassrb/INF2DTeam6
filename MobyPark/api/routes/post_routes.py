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
    TransactionData,
    Reservation,
    ParkingLot,
    ParkingLotCoordinates,
    User)

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
    endpoint = f"{request.method} {request.url.path}"
    Logger.log(current_user, endpoint)
    
    from MobyPark.api.app import connection
    # Truncate all tables
    connection.cursor.execute(
        "TRUNCATE TABLE users, parking_lots, reservations, payments, t_data, vehicles, sessions"
    )
    
    return {"Server message": "All data reset successfully"}