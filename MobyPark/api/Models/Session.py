from datetime import datetime
from .Vehicle import Vehicle
from .ParkingLot import ParkingLot
from .User import User

class Session:

    def __init__(self,
                 id: int,
                 session_id: int,
                 parking_lot: ParkingLot,
                 vehicle: Vehicle,
                 licenseplate: str,
                 started: datetime,
                 stopped: datetime,
                 user: User,
                 username: str,
                 duration_minutes: int,
                 cost: float,
                 payment_status: str):
        
        self.id = id
        self.session_id = session_id
        self.parking_lot = parking_lot
        self.vehicle = vehicle
        self.licenseplate = licenseplate
        self.started = started
        self.stopped = stopped
        self.user = user
        self.username = username
        self.duration_minutes = duration_minutes
        self.cost = cost
        self.payment_status = payment_status


    def __repr__(self):
        return f"session: {self.id}"
        