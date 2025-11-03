from datetime import datetime

class Vehicle:

    def __init__(self,
                  id: str,
                  user_id: str,
                  licence_plate: str,
                  make: str,
                  model: str,
                  color: str,
                  year: int,
                  created_at: datetime):
        
        self.id = id
        self.user_id = user_id
        self.license_plate = licence_plate
        self.make = make
        self.model = model
        self.color = color
        self.year = year
        self.created_at = created_at
        