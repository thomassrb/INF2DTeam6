from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Union
from datetime import datetime

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, regex=r"^[A-Za-z0-9_.-]{3,32}$")
    password: str = Field(..., min_length=8)
    name: str = Field(..., max_length=100)
    phone: str
    email: EmailStr
    birth_year: str
    role: Optional[str] = "USER"

class UserLogin(BaseModel):
    username: str
    password: str

class UserProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    password: Optional[str] = Field(None, min_length=8)
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    birth_year: Optional[int] = None

class SessionData(BaseModel):
    id: str
    username: str
    role: str
    name: str
    email: EmailStr
    phone: str
    birth_year: str
    created_at: str
    active: bool = True

class User(BaseModel):
    id: str
    username: str
    password: Optional[str] = None
    name: str
    phone: str
    email: EmailStr
    birth_year: Union[str, int]
    role: str
    active: bool
    created_at: str

class ParkingLotCreate(BaseModel):
    name: str = Field(..., max_length=100)
    location: str
    capacity: int = Field(..., gt=0)
    tariff: Union[int, float] = Field(..., gt=0)
    daytariff: Union[int, float] = Field(..., gt=0)
    address: str
    coordinates: List[float]

class ParkingLotUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    location: Optional[str] = None
    capacity: Optional[int] = Field(None, gt=0)
    hourly_rate: Optional[Union[int, float]] = Field(None, gt=0)
    day_rate: Optional[Union[int, float]] = Field(None, gt=0)
    reserved: Optional[int] = Field(None, ge=0)

class VehicleCreate(BaseModel):
    licenseplate: str = Field(..., min_length=2, max_length=20, regex=r"^[A-Z0-9_-]{2,20}$")
    name: Optional[str] = Field(None, max_length=100)

class VehicleUpdate(BaseModel):
    name: str = Field(..., max_length=100)

class ReservationCreate(BaseModel):
    licenseplate: str = Field(..., min_length=2, max_length=20)
    startdate: str
    enddate: str
    parkinglot: str
    user: Optional[str] = None

class ReservationUpdate(BaseModel):
    licenseplate: str = Field(..., min_length=2, max_length=20)
    startdate: str
    enddate: str
    parkinglot: str
    user: str

class PaymentCreate(BaseModel):
    transaction: str = Field(..., max_length=128, regex=r"^[A-Za-z0-9:_-]{1,128}$")
    amount: Union[int, float] = Field(..., gt=0)

class PaymentRefund(BaseModel):
    amount: Union[int, float] = Field(..., gt=0)
    transaction: Optional[str] = None
    coupled_to: Optional[str] = None

class PaymentUpdate(BaseModel):
    t_data: dict
    validation: str

class SessionStart(BaseModel):
    licenseplate: str = Field(..., min_length=2, max_length=20, regex=r"^[A-Z0-9_-]{2,20}$")

class SessionStop(BaseModel):
    licenseplate: str = Field(..., min_length=2, max_length=20, regex=r"^[A-Z0-9_-]{2,20}$")


class Session(BaseModel):
    licenseplate: str
    started: str
    stopped: Optional[str] = None
    user: str


class ParkingLotSession(BaseModel):
    session_id: str
    parking_lot_id: str
    licenseplate: str
    started: str
    stopped: Optional[str] = None
    user: str
