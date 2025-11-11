from datetime import datetime

class Reservation:

    def __init__(self,
                 id: str,
                 user_id: str, # will change to user object later on
                 parking_lot_id: str, # will change to parking_lot object later on
                 vehicle_id: str, # will change to vehicle object later on
                 start_time: datetime,
                 end_time: datetime,
                 status: str,
                 created_at: datetime,
                 cost: float):
        
        self.id = id
        self.user_id = user_id
        self.parking_lot_id = parking_lot_id
        self.vehicle_id = vehicle_id
        self.start_time = start_time
        self.end_time = end_time
        self.status = status
        self.created_at = created_at
        self.cost = cost
        