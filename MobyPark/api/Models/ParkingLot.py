from datetime import datetime

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
                 created_at: datetime):
        # might add coordinate attribute to make it more compact
        
        self.id = id
        self.name = name
        self.location = location
        self.address = address
        self.capacity = capacity
        self.reserved = reserved
        self.tariff = tariff
        self.daytarrif = daytariff
        self.created_at = created_at
        