from datetime import datetime
from pydantic import BaseModel

class TransactionData(BaseModel):
    id: str
    amount: float
    date: datetime
    method: str
    issuer: str
    bank: str

        