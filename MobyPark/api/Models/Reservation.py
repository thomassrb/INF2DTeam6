from datetime import datetime
from pydantic import BaseModel
from MobyPark.api.Models.Vehicle import Vehicle
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.User import User

class Reservation(BaseModel):
    user: User|None=None
    parking_lot: ParkingLot|None=None
    vehicle: Vehicle|None=None
    start_time: datetime
    end_time: datetime
    status: str
    created_at: datetime
    cost: float
    id: int|None=None
