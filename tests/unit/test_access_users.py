from datetime import datetime

from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.Models.User import User


def test_access_users_add_and_get_by_username(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))
    access = AccessUsers(conn=conn)

    now = datetime.now().replace(microsecond=0)
    user = User(
        username="unit_user",
        name="Unit User",
        email="unit_user@example.com",
        password="pw",
        created_at=now,
        phone="000",
        role="USER",
        birth_year=2000,
        active=True,
    )

    access.add_user(user)
    assert user.id is not None

    fetched = access.get_user_byusername("unit_user")
    assert fetched is not None
    assert fetched.id == user.id
    assert fetched.email == "unit_user@example.com"
    assert fetched.created_at == now

    conn.close_connection()


def test_access_users_update_and_delete(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))
    access = AccessUsers(conn=conn)

    now = datetime.now().replace(microsecond=0)
    user = User(
        username="unit_user2",
        name="Unit User 2",
        email="unit_user2@example.com",
        password="pw",
        created_at=now,
        phone="111",
        role="USER",
        birth_year=1999,
        active=True,
    )
    access.add_user(user)

    user.name = "Renamed"
    user.phone = "222"
    access.update_user(user)

    fetched = access.get_user_byid(user.id)
    assert fetched is not None
    assert fetched.name == "Renamed"
    assert fetched.phone == "222"

    access.delete_user(user)
    assert access.get_user_byid(user.id) is None

    conn.close_connection()
