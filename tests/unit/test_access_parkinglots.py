from datetime import datetime

from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess.AccessParkingLots import AccessParkingLots
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates


def test_access_parkinglots_add_and_get(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))
    access = AccessParkingLots(conn=conn)

    now = datetime.now().replace(microsecond=0)
    coords = ParkingLotCoordinates(lng=4.0, lat=52.0)
    lot = ParkingLot(
        id=None,
        name="Unit Lot",
        location="Unit City",
        address="Unit Address 1",
        capacity=10,
        reserved=0,
        tariff=2.0,
        daytariff=10.0,
        coordinates=coords,
        created_at=now,
    )

    ok = access.add_parking_lot(parkinglot=lot)
    assert ok is True
    assert lot.id is not None

    fetched = access.get_parking_lot(id=lot.id)
    assert fetched is not None
    assert fetched.id == lot.id
    assert fetched.name == "Unit Lot"
    assert fetched.coordinates.lng == 4.0
    assert fetched.coordinates.lat == 52.0

    conn.close_connection()


def test_access_parkinglots_get_missing_returns_none(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))
    access = AccessParkingLots(conn=conn)

    assert access.get_parking_lot(id=999999) is None

    conn.close_connection()
