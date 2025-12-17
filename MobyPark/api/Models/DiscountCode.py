from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel


class DiscountCode:
    def __init__(
        self,
        id: int,
        code: str,
        discount_percentage: int,
        max_uses: Optional[int] = None,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        created_by: Optional[int] = None,
        created_at: Optional[datetime] = None,
        is_active: bool = True
    ):
        self.id = id
        self.code = code.upper()
        self.discount_percentage = min(100, max(0, discount_percentage))
        self.max_uses = max_uses
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.created_by = created_by
        self.created_at = created_at or datetime.now()
        self.is_active = is_active
        self.uses = 0

    def is_valid(self) -> bool:
        """Check if the discount code is currently valid"""
        now = datetime.now()
        if not self.is_active:
            return False
        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_until and now > self.valid_until:
            return False
        if self.max_uses is not None and self.uses >= self.max_uses:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert the discount code to a dictionary"""
        return {
            'id': self.id,
            'code': self.code,
            'discount_percentage': self.discount_percentage,
            'max_uses': self.max_uses,
            'uses': self.uses,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active
        }


class DiscountCodeResponse(BaseModel):
    id: int
    code: str
    discount_percentage: int
    max_uses: Optional[int] = None
    uses: int = 0
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    created_by: Optional[int] = None
    created_at: Optional[str] = None
    is_active: bool = True

    class Config:
        orm_mode = True


class DiscountCodeCreate(BaseModel):
    code: str
    discount_percentage: int
    max_uses: Optional[int] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None


class ApplyDiscountRequest(BaseModel):
    code: str
    amount: float


class ApplyDiscountResponse(BaseModel):
    success: bool
    discount_amount: float
    final_amount: float
    message: str

    def dict(self, **kwargs):
        return {
            'success': self.success,
            'discount_amount': round(self.discount_amount, 2),
            'final_amount': round(self.final_amount, 2),
            'message': self.message
        }