import math
from datetime import datetime, timedelta
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates

import pytest

from MobyPark.api import session_calculator as sc

def create_parking_lot(tariff=2.5, daytariff=12.0):
    coordinates = ParkingLotCoordinates(latitude=0.0, longitude=0.0)
    return ParkingLot(
        id="1",
        name="Test Parking",
        location="Test Location",
        address="Test Address",
        capacity=100,
        reserved=0,
        tariff=tariff,
        daytariff=daytariff,
        coordinates=coordinates,
        created_at=datetime.now()
    )

def create_mock_session(start_time, end_time=None):
    class MockSession:
        def __init__(self, started, stopped=None):
            self.started = started
            self.stopped = stopped
    return MockSession(start_time, end_time)

def test_price_is_zero_for_parking_under_3_minutes():
    now = datetime.now()
    session = create_mock_session(now, now + timedelta(seconds=100))
    parking_lot = create_parking_lot()
    price, hours, days = sc.calculate_price(parking_lot, session)
    assert price == 0.0
    assert hours == 1

def test_hourly_vs_day_cap():
    now = datetime.now()
    session = create_mock_session(now, now + timedelta(hours=5))
    parking_lot = create_parking_lot(tariff=2.5, daytariff=12.0)
    price, hours, days = sc.calculate_price(parking_lot, session)
    assert price == 12.0
    assert hours == 5

def test_calculates_hourly_price():
    now = datetime.now()
    session = create_mock_session(now, now + timedelta(hours=2))
    parking_lot = create_parking_lot(tariff=3.0, daytariff=50.0)
    price, hours, days = sc.calculate_price(parking_lot, session)
    assert price == 6.0
    assert hours == 2

def test_unparseable_returns_zero():
    class MockSession:
        def __init__(self):
            self.started = "invalid-date"
            self.stopped = None
    
    parking_lot = create_parking_lot()
    price, hours, days = sc.calculate_price(parking_lot, MockSession())
    assert price == 0.0 and hours == 0 and days == 0