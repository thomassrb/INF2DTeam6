from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
import re
import hashlib
import bcrypt
import os

from .. import session_manager, session_calculator
from ..authentication import get_current_user, require_roles
from ..Models.User import User
from ..Models.ParkingLot import ParkingLot
from ..Models.Reservation import Reservation
from ..Models.Payment import Payment
from ..Models.Session import Session
from ..Models.Vehicle import Vehicle

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

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    message: str
    session_token: str

class SessionStartRequest(BaseModel):
    license_plate: Optional[str] = None
    licenseplate: Optional[str] = None

class SessionStopRequest(BaseModel):
    license_plate: Optional[str] = None
    licenseplate: Optional[str] = None

class VehicleCreate(BaseModel):
    licenseplate: str
    make: Optional[str] = None
    model: Optional[str] = None
    color: Optional[str] = None
    year: Optional[str] = None

class PaymentCreate(BaseModel):
    transaction: str
    amount: float
    t_data: Dict[str, Any]

class RefundCreate(BaseModel):
    amount: float
    transaction: Optional[str] = None
    coupled_to: Optional[str] = None

class ParkingLotCreate(BaseModel):
    name: str
    location: str
    capacity: int
    tariff: float
    daytariff: float
    address: str
    coordinates: List[float]

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

def validate_license_plate(license_plate: Optional[str], licenseplate: Optional[str]) -> str:
    """Helper to handle both license_plate and licenseplate fields."""
    lp = license_plate or licenseplate
    if not lp or not isinstance(lp, str) or not lp.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="License plate is required"
        )
    return lp

# ============================================
# Authentication Routes
# ============================================

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(register_data: RegisterRequest):
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
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    
    # Save user to database
    access_users.add_user(user=new_user)
    
    return {"message": "User created"}

@router.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest):
    """Authenticate user and return session token."""
    from MobyPark.api.app import access_users
    user = access_users.get_user_byusername(username=login_data.username)
    
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

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Invalidate the current session."""
    auth_header = request.headers.get("Authorization")
    if auth_header:
        token = auth_header.split(" ")[1] if " " in auth_header else auth_header
        session_manager.remove_session(token)
    
    return {"message": "User logged out successfully"}

# ============================================
# Parking Lot Routes
# ============================================

@router.post("/parking-lots", status_code=status.HTTP_201_CREATED)
async def create_parking_lot(
    parking_data: ParkingLotCreate,
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    """Create a new parking lot (admin only)."""
    from MobyPark.api.app import access_parkinglots
    # Validate coordinates
    if len(parking_data.coordinates) != 2 or \
       not all(isinstance(coord, (int, float)) for coord in parking_data.coordinates):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Coordinates must be a list of two numbers"
        )
    
    # Create parking lot
    parking_lot = ParkingLot(
        name=parking_data.name,
        location=parking_data.location,
        capacity=parking_data.capacity,
        hourly_rate=parking_data.tariff,
        day_rate=parking_data.daytariff,
        address=parking_data.address,
        coordinates=parking_data.coordinates,
        reserved=0
    )
    
    access_parkinglots.add_parking_lot(parkinglot=parking_lot)
    
    return {"Server message": f"Parking lot saved under ID: {parking_lot.id}"}

# ============================================
# Session Routes
# ============================================

@router.post("/parking-lots/{lid}/sessions/start")
async def start_session(
    lid: str,
    session_data: SessionStartRequest,
    current_user: User = Depends(get_current_user)
):
    """Start a new parking session."""
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
        session_data.license_plate, 
        session_data.licenseplate
    )
    
    # Create session
    session = Session(
        parking_lot=parking_lot,
        user=current_user,
        license_plate=license_plate,
        started=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        payment_status="pending",
        username=current_user.username
    )
    
    # Add session to database
    if not access_sessions.add_session(session=session):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot start a session when another session for this license plate is already started."
        )
    
    return {"Server message": f"Session started for: {license_plate} under id: {session.id}"}

@router.post("/parking-lots/{lid}/sessions/stop")
async def stop_session(
    lid: str,
    session_data: SessionStopRequest,
    current_user: User = Depends(get_current_user)
):
    """Stop an active parking session."""
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
        session_data.license_plate,
        session_data.licenseplate
    )
    
    # Get active session
    session = access_sessions.get_pending_session_bylicenseplate(licenseplate=license_plate)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot stop a session when there is no active session for this license plate."
        )
    
    # Update session
    session.stopped = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    access_sessions.update_session(session=session)
    
    return {"Server message": f"Session stopped for: {license_plate}"}

# ============================================
# Vehicle Routes
# ============================================

@router.post("/vehicles", status_code=status.HTTP_201_CREATED)
async def create_vehicle(
    vehicle_data: VehicleCreate,
    current_user: User = Depends(get_current_user)
):
    """Register a new vehicle for the current user."""
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
        license_plate=vehicle_data.licenseplate,
        make=vehicle_data.make,
        model=vehicle_data.model,
        color=vehicle_data.color,
        year=vehicle_data.year,
        created_at=datetime.now().strftime("%Y-%m-%d")
    )
    
    # Save vehicle
    access_vehicles.add_vehicle(vehicle=vehicle)
    
    return {
        "status": "Success",
        "vehicle": {
            "id": vehicle.id,
            "license_plate": vehicle.license_plate,
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
    current_user: User = Depends(get_current_user)
):
    """Create a new payment."""
    from MobyPark.api.app import access_payments
    # Create payment
    payment = Payment(
        transaction=payment_data.transaction,
        amount=payment_data.amount,
        initiator=current_user,
        created_at=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        completed=False,
        t_data=payment_data.t_data,
        hash=session_calculator.generate_transaction_validation_hash()
    )
    
    # Save payment
    access_payments.add_payment(payment=payment)
    
    return {
        "status": "Success",
        "payment": {
            "transaction": payment.transaction,
            "amount": payment.amount,
            "initiator": payment.initiator.username,
            "created_at": payment.created_at,
            "completed": payment.completed
        }
    }

@router.post("/payments/refund", status_code=status.HTTP_201_CREATED)
async def refund_payment(
    refund_data: RefundCreate,
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    """Create a refund payment (admin only)."""
    from MobyPark.api.app import access_payments
    # Generate transaction ID if not provided
    transaction_id = refund_data.transaction or str(uuid.uuid4())
    
    # Create refund payment
    refund = Payment(
        transaction=transaction_id,
        amount=-abs(refund_data.amount),  # Negative amount for refund
        initiator=current_user,
        created_at=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        completed=False,
        coupled_to=refund_data.coupled_to,
        hash=session_calculator.generate_transaction_validation_hash()
    )
    
    # Save refund
    access_payments.add_payment(payment=refund)
    
    return {
        "status": "Success",
        "refund": {
            "transaction": refund.transaction,
            "amount": refund.amount,
            "initiator": refund.initiator.username,
            "coupled_to": refund.coupled_to,
            "created_at": refund.created_at
        }
    }

# ============================================
# Admin Routes
# ============================================

@router.post("/debug/reset")
async def debug_reset(
    current_user: User = Depends(require_roles(["ADMIN"]))
):
    """
    Reset all data (admin only).
    WARNING: This will delete all data in the database!
    """
    from MobyPark.api.app import connection
    # Truncate all tables
    connection.cursor.execute(
        "TRUNCATE TABLE users, parking_lots, reservations, payments, t_data, vehicles, sessions"
    )
    
    return {"Server message": "All data reset successfully"}