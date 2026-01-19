from datetime import datetime

from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.DataAccess.AccessVehicles import AccessVehicles
from MobyPark.api.Models.User import User
from MobyPark.api.Models.Vehicle import Vehicle


def test_access_vehicles_get_vehicles_by_user_returns_users_vehicles(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    access_users = AccessUsers(conn=conn)
    access_vehicles = AccessVehicles(conn=conn)

    now = datetime.now().replace(microsecond=0)

    user = User(
        username="veh_by_user",
        name="Vehicle By User",
        email="veh_by_user@example.com",
        password="pw",
        created_at=now,
        phone="000",
        role="USER",
        birth_year=2000,
        active=True,
    )
    access_users.add_user(user)

    v1 = Vehicle(
        user=user,
        licenseplate="BYUSER-1",
        make="VW",
        model="Golf",
        color="Blue",
        year=2020,
        created_at=now,
    )
    v2 = Vehicle(
        user=user,
        licenseplate="BYUSER-2",
        make="VW",
        model="Polo",
        color="Red",
        year=2021,
        created_at=now,
    )
    access_vehicles.add_vehicle(v1)
    access_vehicles.add_vehicle(v2)

    vehicles = access_vehicles.get_vehicles_byuser(user)
    assert isinstance(vehicles, list)
    assert {v.licenseplate for v in vehicles} == {"BYUSER-1", "BYUSER-2"}

    conn.close_connection()
