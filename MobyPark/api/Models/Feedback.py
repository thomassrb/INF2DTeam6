from pydantic import BaseModel
from .ParkingLot import ParkingLot
from .User import User
from datetime import datetime

class Feedback(BaseModel):
    id: int
    user: User
    parking_lot: ParkingLot
    rating: int
    comment: str
    created_at: datetime