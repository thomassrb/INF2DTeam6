from datetime import datetime
from pydantic import BaseModel
from MobyPark.api.Models.User import User
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.Session import Session
from MobyPark.api.Models.TransanctionData import TransactionData

class Payment(BaseModel):
    id: str
    amount: float
    initiator: str
    user: User
    created_at: datetime
    completed: datetime
    hash: str
    session: Session
    parking_lot: ParkingLot
    t_data: TransactionData

