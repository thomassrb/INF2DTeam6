class ParkingLotCoordinates:

    def __init__(self,
                 lng: float,
                 lat: float,
                 id: int|None=None):
    
        self.id = id
        self.lng = lng
        self.lat = lat

        
    def __repr__(self):
        return self.__dict__