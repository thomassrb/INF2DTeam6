from datetime import datetime
from pydantic import BaseModel
from .ParkingLotCoordinates import ParkingLotCoordinates

class ParkingLot(BaseModel):
        name: str
        location: str
        address: str
        capacity: int
        reserved: int
        tariff: float
        daytariff: float
        coordinates: ParkingLotCoordinates
        created_at: datetime
        id: int|None=None

