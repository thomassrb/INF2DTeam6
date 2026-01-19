from typing import Optional, Dict, Any
import os
import sys
import pathlib
import hashlib
from MobyPark.api import authentication
project_root = str(pathlib.Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)
from typing import Any
from fastapi import FastAPI, Depends, HTTPException, Request, status, responses
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess import (
    AccessParkingLots,
    AccessPayments,
    AccessReservations,
    AccessSessions,
    AccessUsers,
    AccessVehicles,
    AccessFreeParking,
    Logger
)
from MobyPark.api.storage_utils import load_parking_lot_data,load_reservation_data,save_parking_lot_data,save_reservation_data,load_vehicles_data,save_vehicles_data,load_user_data,save_user_data,load_payment_data,save_payment_data

from MobyPark.api.Models.User import User
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates
from MobyPark.api import session_manager
from MobyPark.api.routes.delete_routes import router as delete_router
from MobyPark.api.routes.get_routes import router as get_router
from MobyPark.api.routes.post_routes import router as post_router
from MobyPark.api.routes.put_routes import router as put_router
from typing import Optional
import os
get_current_user = authentication.get_current_user 
require_roles = authentication.require_roles
# Gebruik dezelfde data directory als de rest van het project
DATA_DIR = (
    os.environ.get("MOBYPARK_DB_DIR")
    or os.environ.get("MOBYPARK_DATA_DIR")
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "MobyPark-api-data", "pdata")
)
os.makedirs(DATA_DIR, exist_ok=True)

LOG_DIR = (
    os.environ.get("MOBYPARK_LOG_DIR")
    or os.environ.get("MOBYPARK_LOG_DIR")
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "Logs")
)
os.makedirs(DATA_DIR, exist_ok=True)

db_path = os.path.join(DATA_DIR, "MobyParkData.db")
connection = DBConnection(database_path=db_path)
access_parkinglots = AccessParkingLots(conn=connection)
access_payments = AccessPayments(conn=connection)
access_reservations = AccessReservations(conn=connection)
access_sessions = AccessSessions(conn=connection)
access_users = AccessUsers(conn=connection)
access_vehicles = AccessVehicles(conn=connection)
access_free_parking = AccessFreeParking(connection=connection)
Logger = Logger(path=LOG_DIR)

app = FastAPI(title="MobyPark API", version="1.0.0")

# Include the routers
app.include_router(get_router, prefix="/api")
app.include_router(post_router, prefix="/api")
app.include_router(delete_router, prefix="/api")
app.include_router(put_router, prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.responses import JSONResponse
from typing import Any

# Simple in-memory index so we can reliably detect active sessions per lot+license plate
ACTIVE_SESSION_KEYS: set[str] = set()

BILLING_DATA: dict[str, list[dict]] = {}

def _user_attr(user: Any, attr: str) -> Any:
    """Helper: works for both dict-like users and User model instances."""
    if isinstance(user, dict):
        return user.get(attr)
    return getattr(user, attr, None)


class RegisterRequest(BaseModel):
    username: str
    password: str
    name: str
    phone: str
    email: str
    birth_year: str
    role: Optional[str] = "USER"


class LoginRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None

class ParkingLotCreate(BaseModel):
    name: str
    location: str
    # return 400
    capacity: Optional[int] = None
    tariff: float
    daytariff: float
    address: str
    coordinates: list[float]
from fastapi.responses import JSONResponse


class ReservationCreate(BaseModel):
    parkinglot: str
    start: Optional[str] = None
    end: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    license_plate: Optional[str] = None
    licenseplate: Optional[str] = None
    user: Optional[str] = None


class ReservationUpdate(BaseModel):
    parkinglot: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    license_plate: Optional[str] = None
    licenseplate: Optional[str] = None
    user: Optional[str] = None


class VehicleCreate(BaseModel):
    licenseplate: str
    name: Optional[str] = None


class PaymentCreate(BaseModel):
    transaction: str
    amount: float


class PaymentUpdate(BaseModel):
    validation: str
    t_data: Dict[str, Any]


class RefundCreate(BaseModel):
    amount: float
    transaction: Optional[str] = None
    coupled_to: Optional[str] = None


class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None



def get_current_user(request: Request) -> User:
    """FastAPI dependency to get current user from session token in Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header missing")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header format")
    token = parts[1]
    user = session_manager.get_session(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session token")
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        return user

    return dependency

class SessionStartRequest(BaseModel):
    license_plate: Optional[str] = None
    licenseplate: Optional[str] = None

@app.post("/sessions/start")
async def start_session(body: SessionStartRequest, user: User = Depends(get_current_user)):
    if not body.licenseplate:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "Missing or invalid field: licenseplate",
                "field": "licenseplate",
            },
        )

@app.get("/", response_class=PlainTextResponse)
async def root():
    return "👍 200 OK - MobyPark API is running"

