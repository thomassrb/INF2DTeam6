from datetime import datetime
from pydantic import BaseModel
from MobyPark.api.Models.Vehicle import Vehicle
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.User import User

class Session(BaseModel):
    parking_lot: ParkingLot|None=None
    vehicle: Vehicle|None=None
    licenseplate: str
    started: datetime
    stopped: datetime|None=None
    user: User|None=None
    username: str
    duration_minutes: int|None=None
    cost: float
    payment_status: str
    id: int|None=None
