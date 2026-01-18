from datetime import datetime, timedelta

from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess.AccessParkingLots import AccessParkingLots
from MobyPark.api.DataAccess.AccessSessions import AccessSessions
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates
from MobyPark.api.Models.Session import Session
from MobyPark.api.Models.User import User


def test_access_sessions_pending_lookup_and_update_persists_stop(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    access_users = AccessUsers(conn=conn)
    access_parkinglots = AccessParkingLots(conn=conn)
    access_sessions = AccessSessions(conn=conn)

    now = datetime.now().replace(microsecond=0)

    user = User(
        username="unit_sess_user",
        name="Unit Sess User",
        email="unit_sess_user@example.com",
        password="pw",
        created_at=now,
        phone="000",
        role="USER",
        birth_year=2000,
        active=True,
    )
    access_users.add_user(user)

    lot = ParkingLot(
        id=None,
        name="Unit Lot",
        location="Unit City",
        address="Unit Address Sessions",
        capacity=10,
        reserved=0,
        tariff=2.0,
        daytariff=10.0,
        coordinates=ParkingLotCoordinates(lng=4.0, lat=52.0),
        created_at=now,
    )
    access_parkinglots.add_parking_lot(parkinglot=lot)

    session = Session(
        parking_lot=lot,
        vehicle=None,
        licenseplate="UNIT-SESSION-1",
        started=now,
        stopped=None,
        username=user.username,
        user=user,
        duration_minutes=None,
        cost=0.0,
        payment_status="pending",
        id=None,
        session_id=1,
    )
    access_sessions.add_session(session=session)
    assert session.id is not None

    pending = access_sessions.get_pending_session_bylicenseplate("UNIT-SESSION-1")
    assert pending is not None
    assert pending.id == session.id

    session.stopped = now + timedelta(minutes=5)
    session.payment_status = "done"
    access_sessions.update_session(session=session)

    fetched = access_sessions.get_session(id=session.id)
    assert fetched is not None
    assert fetched.stopped is not None
    assert fetched.payment_status == "done"

    conn.close_connection()


def test_access_sessions_pending_lookup_missing_returns_none(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))
    access_sessions = AccessSessions(conn=conn)

    assert access_sessions.get_pending_session_bylicenseplate("NO-SUCH-PLATE") is None

    conn.close_connection()
