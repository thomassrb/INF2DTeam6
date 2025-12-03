from datetime import datetime
from .ParkingLotCoordinates import ParkingLotCoordinates

class ParkingLot:

    def __init__(self,
                 id: str,
                 name: str,
                 location: str,
                 address: str,
                 capacity: int,
                 reserved: int,
                 tariff: float,
                 daytariff: float,
                 coordinates: ParkingLotCoordinates,
                 created_at: datetime):

        
        self.id = id
        self.name = name
        self.location = location
        self.address = address
        self.capacity = capacity
        self.reserved = reserved
        self.tariff = tariff
        self.daytariff = daytariff
        self.coordinates = coordinates
        self.created_at = created_at

    def __repr__(self):
        return self.__dict__
        