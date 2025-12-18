from datetime import datetime, time as dt_time
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, validator, Field
import random
import string

class LocationRule(BaseModel):
    """Rules for location-based discount application"""
    parking_lot_ids: List[int] = Field(..., description="List of parking lot IDs where this discount applies")
    is_blacklist: bool = Field(False, description="If True, the discount does NOT apply to these locations")

class TimeRule(BaseModel):
    """Rules for time-based discount application"""
    days_of_week: List[int] = Field(..., description="List of days (0-6, where 0 is Monday) when discount applies")
    time_ranges: List[Dict[str, str]] = Field(
        ..., 
        description="List of time ranges in format {'start': 'HH:MM', 'end': 'HH:MM'}"
    )

    @validator('time_ranges')
    def validate_time_ranges(cls, v):
        for tr in v:
            try:
                dt_time.fromisoformat(tr['start'])
                dt_time.fromisoformat(tr['end'])
            except (ValueError, KeyError) as e:
                raise ValueError(f"Invalid time range format: {e}")
        return v


class DiscountCode:
    CODE_CHARS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
    CODE_LENGTH = 10

    def __init__(
        self,
        id: int,
        code: str = None,
        discount_percentage: int = None,
        max_uses: Optional[int] = None,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        created_by: Optional[int] = None,
        created_at: Optional[datetime] = None,
        is_active: bool = True,
        location_rules: Optional[Dict] = None,
        time_rules: Optional[Dict] = None,
        auto_generate_code: bool = True
    ):
        self.id = id
        self.code = self._generate_code() if (not code and auto_generate_code) else (code.upper() if code else None)
        self.discount_percentage = min(100, max(0, discount_percentage)) if discount_percentage is not None else None
        self.max_uses = max_uses
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.created_by = created_by
        self.created_at = created_at or datetime.now()
        self.is_active = is_active
        self.uses = 0
        self.location_rules = LocationRule(**(location_rules or {})) if location_rules else None
        self.time_rules = TimeRule(**(time_rules or {})) if time_rules else None
        
        if not auto_generate_code and code:
            self._validate_code(code)
    
    @classmethod
    def _generate_code(cls) -> str:
        """Generate a random alphanumeric code without ambiguous characters"""
        return ''.join(random.choices(cls.CODE_CHARS, k=cls.CODE_LENGTH))
    
    @classmethod
    def _validate_code(cls, code: str) -> None:
        """Validate the discount code format"""
        if not code or len(code) != cls.CODE_LENGTH:
            raise ValueError(f"Code must be exactly {cls.CODE_LENGTH} characters long")
        if not all(c in cls.CODE_CHARS for c in code.upper()):
            invalid_chars = set(code.upper()) - set(cls.CODE_CHARS)
            raise ValueError(f"Code contains invalid characters: {', '.join(invalid_chars)}")

    def is_valid(self) -> bool:
        """Check if the discount code is currently valid"""
        now = datetime.now()
        
        print(f"\nChecking code validity:")
        print(f"- Code: {self.code}")
        print(f"- Is active: {self.is_active}")
        print(f"- Current time: {now}")
        print(f"- Valid from: {self.valid_from}")
        print(f"- Valid until: {self.valid_until}")
        print(f"- Uses: {self.uses}/{self.max_uses if self.max_uses else 'unlimited'}")
        
        if not self.is_active:
            print("Code is not active")
            return False
            
        if self.valid_from and now < self.valid_from:
            print(f"Code not valid yet. Valid from: {self.valid_from}")
            return False
            
        if self.valid_until and now > self.valid_until:
            print(f"Code has expired. Valid until: {self.valid_until}")
            return False
            
        if self.max_uses is not None and self.uses >= self.max_uses:
            print(f"Code has reached maximum uses: {self.uses}/{self.max_uses}")
            return False
            
        print("Code is valid")
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
            'is_active': self.is_active,
            'location_rules': self.location_rules.dict() if self.location_rules else None,
            'time_rules': self.time_rules.dict() if self.time_rules else None
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
    location_rules: Optional[Dict] = None
    time_rules: Optional[Dict] = None

    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class DiscountCodeCreate(BaseModel):
    code: Optional[str] = Field(
        None, 
        min_length=6, 
        max_length=6,
        description="Optional 6-character code. If not provided, one will be generated"
    )
    discount_percentage: int = Field(..., gt=0, le=100)
    max_uses: Optional[int] = Field(None, gt=0)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    location_rules: Optional[Dict] = None
    time_rules: Optional[Dict] = None
    auto_generate_code: bool = True

    @validator('code')
    def validate_code(cls, v):
        if v is not None:
            v = ''.join(c.upper() for c in v if not c.isspace())
            allowed_chars = set('23456789ABCDEFGHJKLMNPQRSTUVWXYZ')
            if not all(c in allowed_chars for c in v):
                raise ValueError("Code can only contain uppercase letters and numbers, excluding ambiguous characters")
        return v
    
    @validator('valid_until')
    def validate_dates(cls, v, values):
        if 'valid_from' in values and v and values['valid_from'] and v <= values['valid_from']:
            raise ValueError("valid_until must be after valid_from")
        return v


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