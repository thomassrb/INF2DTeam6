from datetime import datetime

from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.DataAccess.AccessParkingLots import AccessParkingLots
from MobyPark.api.DataAccess.AccessReservations import AccessReservations
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.DataAccess.AccessVehicles import AccessVehicles
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates
from MobyPark.api.Models.Reservation import Reservation
from MobyPark.api.Models.User import User
from MobyPark.api.Models.Vehicle import Vehicle


def test_access_reservations_add_and_get_by_id(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    access_users = AccessUsers(conn=conn)
    access_vehicles = AccessVehicles(conn=conn)
    access_parkinglots = AccessParkingLots(conn=conn)
    access_reservations = AccessReservations(conn=conn)

    now = datetime.now().replace(microsecond=0)

    user = User(
        username="unit_res_user",
        name="Unit Res User",
        email="unit_res_user@example.com",
        password="pw",
        created_at=now,
        phone="000",
        role="USER",
        birth_year=2000,
        active=True,
    )
    access_users.add_user(user)

    vehicle = Vehicle(
        user=user,
        licenseplate="UNIT-RES-1",
        make="Make",
        model="Model",
        color="Blue",
        year=2020,
        created_at=now,
    )
    access_vehicles.add_vehicle(vehicle=vehicle)

    lot = ParkingLot(
        id=None,
        name="Unit Lot",
        location="Unit City",
        address="Unit Address Reservations",
        capacity=10,
        reserved=0,
        tariff=2.0,
        daytariff=10.0,
        coordinates=ParkingLotCoordinates(lng=4.0, lat=52.0),
        created_at=now,
    )
    access_parkinglots.add_parking_lot(parkinglot=lot)

    start = now
    end = now

    reservation = Reservation(
        user=user,
        parking_lot=lot,
        vehicle=vehicle,
        start_time=start,
        end_time=end,
        status="CREATED",
        created_at=now,
        cost=0.0,
        id=None,
    )

    access_reservations.add_reservation(reservation=reservation)
    assert reservation.id is not None

    fetched = access_reservations.get_reservation(id=reservation.id)
    assert fetched is not None
    assert fetched.id == reservation.id
    assert fetched.user is not None
    assert fetched.user.username == user.username
    assert fetched.vehicle is not None
    assert fetched.vehicle.licenseplate == vehicle.licenseplate
    assert fetched.parking_lot is not None
    assert fetched.parking_lot.address == lot.address

    conn.close_connection()
