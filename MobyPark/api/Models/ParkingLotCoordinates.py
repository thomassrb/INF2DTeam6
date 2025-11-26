class ParkingLotCoordinates:

    def __init__(self,
                 id: str,
                 lng: float,
                 lat: float):
    
        self.id = id
        self.lng = lng
        self.lat = lat

        
    def __repr__(self):
        return f"coordinates obj: {self.id}"