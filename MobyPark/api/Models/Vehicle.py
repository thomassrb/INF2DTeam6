from datetime import datetime
from .User import User

class Vehicle:

    def __init__(self,
                  id: str,
                  user: User,
                  licenseplate: str,
                  make: str,
                  model: str,
                  color: str,
                  year: int,
                  created_at: datetime):
        
        self.id = id
        self.user = user
        self.licenseplate = licenseplate
        self.make = make
        self.model = model
        self.color = color
        self.year = year
        self.created_at = created_at


    def __repr__(self):
        return self.licenseplate
        