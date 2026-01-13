from datetime import datetime
from pydantic import BaseModel
from MobyPark.api.Models.Vehicle import Vehicle
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.User import User

class Session(BaseModel):
    session_id: int
    parking_lot: ParkingLot
    vehicle: Vehicle
    licenseplate: str
    started: datetime
    stopped: datetime
    user: User
    username: str
    duration_minutes: int
    cost: float
    payment_status: str
    id: int|None=None
