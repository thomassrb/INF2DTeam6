from datetime import datetime
from MobyPark.api.Models.Vehicle import Vehicle
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.User import User

class Reservation:

    def __init__(self,
                 user: User,
                 parking_lot: ParkingLot,
                 vehicle: Vehicle,
                 start_time: datetime,
                 end_time: datetime,
                 status: str,
                 created_at: datetime,
                 cost: float,
                 id: int|None=None):
        
        self.id = id
        self.user = user
        self.parking_lot = parking_lot
        self.vehicle = vehicle
        self.start_time = start_time
        self.end_time = end_time
        self.status = status
        self.created_at = created_at
        self.cost = cost
        
    
    def __repr__(self):
        return self.__dict__