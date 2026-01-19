from datetime import datetime
from ..Models import User

class FreeParking:
    def __init__(self, id: int, license_plate: str, added_by: User, created_at: datetime):
        self.id = id
        self.license_plate = license_plate
        self.added_by = added_by
        self.created_at = created_at

    def __repr__(self):
        return f"<FreeParking {self.license_plate}>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'license_plate': self.license_plate,
            'added_by': self.added_by.username,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
