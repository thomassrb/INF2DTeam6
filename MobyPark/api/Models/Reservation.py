from datetime import datetime
from Models.Vehicle import Vehicle
from Models.ParkingLot import ParkingLot
from Models.User import User

class Reservation:

    def __init__(self,
                 id: str,
                 user: User,
                 parking_lot: ParkingLot,
                 vehicle: Vehicle,
                 start_time: datetime,
                 end_time: datetime,
                 status: str,
                 created_at: datetime,
                 cost: float):
        
        self.id = id
        self.user = user
        self.parking_lot = parking_lot
        self.vehicle = vehicle
        self.start_time = start_time
        self.end_time = end_time
        self.status = status
        self.created_at = created_at
        self.cost = cost
        