from datetime import datetime
from pydantic import BaseModel
from .User import User

class Vehicle(BaseModel):
    user: User|None=None
    licenseplate: str
    make: str
    model: str
    color: str
    year: int
    created_at: datetime
    id: int|None=None

        