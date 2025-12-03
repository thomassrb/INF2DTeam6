from datetime import datetime
from .User import User
from .ParkingLot import ParkingLot
from .Session import Session
from .TransanctionData import TransactionData

class Payment:

    def __init__(self,
                 id: str,
                 amount: float,
                 initiator: str,
                 user: User,
                 created_at: datetime,
                 completed: datetime,
                 hash: str,
                 session: Session,
                 parking_lot: ParkingLot,
                 t_data: TransactionData):
                 
        
        self.id = id
        self.amount = amount
        self.initiator = initiator
        self.user = user
        self.created_at = created_at
        self.completed = completed
        self.hash = hash
        self.session = session
        self.parking_lot = parking_lot
        self.t_data = t_data

    
    def __repr__(self):
        return self.__dict__
