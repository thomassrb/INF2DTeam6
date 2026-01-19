from datetime import datetime
from pydantic import BaseModel

class User(BaseModel):
    username: str
    name: str
    email: str
    password: str
    created_at: datetime
    phone: str
    role: str
    birth_year: int
    active: bool
    id: int|None=None
    