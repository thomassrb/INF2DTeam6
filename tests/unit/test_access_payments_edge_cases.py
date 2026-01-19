from datetime import datetime

from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess.AccessParkingLots import AccessParkingLots
from MobyPark.api.DataAccess.AccessPayments import AccessPayments
from MobyPark.api.DataAccess.AccessSessions import AccessSessions
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates
from MobyPark.api.Models.Session import Session
from MobyPark.api.Models.User import User


def test_get_payment_by_session_returns_none_when_missing(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    access_users = AccessUsers(conn=conn)
    access_parkinglots = AccessParkingLots(conn=conn)
    access_sessions = AccessSessions(conn=conn)
    access_payments = AccessPayments(conn=conn)

    now = datetime.now().replace(microsecond=0)

    user = User(
        username="unit_pay_user",
        name="Unit Pay User",
        email="unit_pay_user@example.com",
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
        address="Unit Address Payments",
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
        licenseplate="UNIT-PAY-1",
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

    assert access_payments.get_payment_by_session(session) is None

    conn.close_connection()
