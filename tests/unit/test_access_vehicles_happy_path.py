from datetime import datetime

import pytest

from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.DataAccess.AccessVehicles import AccessVehicles
from MobyPark.api.Models.User import User
from MobyPark.api.Models.Vehicle import Vehicle


def test_access_vehicles_add_and_get_by_licenseplate(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    access_users = AccessUsers(conn=conn)
    access_vehicles = AccessVehicles(conn=conn)

    now = datetime.now().replace(microsecond=0)
    user = User(
        username="veh_user",
        name="Vehicle User",
        email="veh_user@example.com",
        password="pw",
        created_at=now,
        phone="000",
        role="USER",
        birth_year=2000,
        active=True,
    )
    access_users.add_user(user)
    assert user.id is not None

    vehicle = Vehicle(
        user=user,
        licenseplate="UNIT-123",
        make="VW",
        model="Golf",
        color="Blue",
        year=2020,
        created_at=now,
    )
    access_vehicles.add_vehicle(vehicle)
    assert vehicle.id is not None

    fetched = access_vehicles.get_vehicle_bylicenseplate("UNIT-123")
    assert fetched is not None
    assert fetched.licenseplate == "UNIT-123"
    assert fetched.user is not None
    assert fetched.user.id == user.id

    conn.close_connection()


def test_access_vehicles_get_by_licenseplate_missing_returns_none(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    access_vehicles = AccessVehicles(conn=conn)

    # This currently crashes if get_vehicle_bylicenseplate doesn't handle None.
    # If your implementation returns None correctly, this test will pass.
    assert access_vehicles.get_vehicle_bylicenseplate("DOES-NOT-EXIST") is None

    conn.close_connection()
