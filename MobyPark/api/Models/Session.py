from datetime import datetime

class Session:

    def __init__(self,
                 id: str,
                 parking_lot_id: str,
                 vehicle_id: str,
                 started: datetime,
                 stopped: datetime,
                 user_id: str,
                 duration_minutes: int,
                 cost: float,
                 payment_status: str):
        
        self.id = id
        self.parking_lot_id = parking_lot_id
        self.vehicle_id = vehicle_id
        self.started = started
        self.stopped = stopped
        self.user_id = user_id
        self.duration_minutes = duration_minutes
        self.cost = cost
        self.payment_status = payment_status
        