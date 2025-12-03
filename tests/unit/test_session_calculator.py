import math
from datetime import datetime, timedelta

import pytest

from MobyPark.api import session_calculator as sc

def fake_parking(tariff=2.5, daytariff=12.0):
    return {"tariff": tariff, "daytariff": daytariff}

def fmt(dt: datetime, fmt="%d-%m-%Y %H:%M:%S"):
    return dt.strftime(fmt)

def create_mock_session(start_time, end_time=None):
    class MockSession:
        def __init__(self, started, stopped=None):
            self.started = started
            self.stopped = stopped
    return MockSession(start_time, end_time)

def test_price_is_zero_for_parking_under_3_minutes():
    now = datetime.now()
    session = create_mock_session(now, now + timedelta(seconds=100))
    price, hours, days = sc.calculate_price(fake_parking(), session)
    assert price == 0.0
    assert hours == 1

def test_hourly_vs_day_cap():
    now = datetime.now()
    session = create_mock_session(now, now + timedelta(hours=5))
    price, hours, days = sc.calculate_price(fake_parking(tariff=2.5, daytariff=12.0), session)
    assert price == 12.0
    assert hours == 5

def test_calculates_hourly_price():
    now = datetime.now()
    session = create_mock_session(now, now + timedelta(hours=2))
    price, hours, days = sc.calculate_price(fake_parking(tariff=3.0, daytariff=50.0), session)
    assert price == 6.0
    assert hours == 2

def test_unparseable_returns_zero():
    class MockSession:
        def __init__(self):
            self.started = "invalid-date"
            self.stopped = None
    
    price, hours, days = sc.calculate_price(fake_parking(), MockSession())
    assert price == 0.0 and hours == 0 and days == 0