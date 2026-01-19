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


def test_reservation_reserved_counter_increment_and_decrement(tmp_path):
    db_path = tmp_path / "test.db"
    conn = DBConnection(str(db_path))

    access_users = AccessUsers(conn=conn)
    access_vehicles = AccessVehicles(conn=conn)
    access_parkinglots = AccessParkingLots(conn=conn)
    access_reservations = AccessReservations(conn=conn)

    now = datetime.now().replace(microsecond=0)

    user = User(
        username="unit_reserved_user",
        name="Unit Reserved User",
        email="unit_reserved_user@example.com",
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
        licenseplate="UNIT-RESERVED-1",
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
        address="Unit Address Reserved Counter",
        capacity=10,
        reserved=0,
        tariff=2.0,
        daytariff=10.0,
        coordinates=ParkingLotCoordinates(lng=4.0, lat=52.0),
        created_at=now,
    )
    access_parkinglots.add_parking_lot(parkinglot=lot)

    reservation = Reservation(
        user=user,
        parking_lot=lot,
        vehicle=vehicle,
        start_time=now,
        end_time=now,
        status="CREATED",
        created_at=now,
        cost=0.0,
        id=None,
    )
    access_reservations.add_reservation(reservation=reservation)
    assert reservation.id is not None

    lot.reserved += 1
    access_parkinglots.update_parking_lot(parkinglot=lot)

    fetched_lot = access_parkinglots.get_parking_lot(id=lot.id)
    assert fetched_lot is not None
    assert fetched_lot.reserved == 1

    access_reservations.delete_reservation(reservation=reservation)

    fetched_lot.reserved -= 1
    access_parkinglots.update_parking_lot(parkinglot=fetched_lot)

    fetched_lot2 = access_parkinglots.get_parking_lot(id=lot.id)
    assert fetched_lot2 is not None
    assert fetched_lot2.reserved == 0

    conn.close_connection()
