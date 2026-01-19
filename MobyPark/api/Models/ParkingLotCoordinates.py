from pydantic import BaseModel

class ParkingLotCoordinates(BaseModel):
        lng: float
        lat: float
        id: int|None=None
