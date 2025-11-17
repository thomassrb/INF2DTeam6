import math
from datetime import datetime, timedelta

import pytest

from MobyPark.api import session_calculator as sc

def fake_parking(tariff=2.5, daytariff=12.0):
    return {"tariff": tariff, "daytariff": daytariff}

def fmt(dt: datetime, fmt="%d-%m-%Y %H:%M:%S"):
    return dt.strftime(fmt)

def test_price_is_zero_for_parking_under_3_minutes():
    now = datetime.now()
    data = {"started": fmt(now), "stopped": fmt(now + timedelta(seconds=100))}
    price, hours, days = sc.calculate_price(fake_parking(), "1", data)
    assert price == 0.0
    assert hours == 1

def test_hourly_vs_day_cap():
    now = datetime.now()

    data = {"started": fmt(now), "stopped": fmt(now + timedelta(hours=5))}
    price, hours, days = sc.calculate_price(fake_parking(tariff=2.5, daytariff=12.0), "1", data)
    assert price == 12.0
    assert hours == 5

def test_calculates_hourly_price_for_iso_zulu_timestamps():
    now = datetime.now()
    data = {"start_time": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "end_time": (now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    price, hours, days = sc.calculate_price(fake_parking(tariff=3.0, daytariff=50.0), "1", data)
    assert price == 6.0
    assert hours == 2

def test_unparseable_returns_zero():
    data = {"started": "invalid-date"}
    price, hours, days = sc.calculate_price(fake_parking(), "1", data)
    assert price == 0.0 and hours == 0 and days == 0