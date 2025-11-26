import sqlite3
from datetime import datetime
from Models.User import User
from Models.ParkingLot import ParkingLot
from Models.ParkingLotCoordinates import ParkingLotCoordinates
from Models.Payment import Payment
from Models.Reservation import Reservation
from Models.Session import Session
from Models.Vehicle import Vehicle
from Models.ParkingLotCoordinates import ParkingLotCoordinates
from Models.TransanctionData import TransactionData
from DataAccess.AccessUsers import AccessUsers
from DataAccess.AccessParkingLots import AccessParkingLots
from DataAccess.AccessVehicles import AccessVehicles
from DataAccess.AccessSessions import AccessSessions
from DataAccess.AccessPayments import AccessPayments
from DataAccess.AccessReservations import AccessReservations
from DBConnection import DBConnection

conn = DBConnection("MobyPark/api/data/MobyParkData.db")
AccessUsers = AccessUsers(conn=conn)
AccessParkingLots = AccessParkingLots(conn=conn)
AccessVehicles = AccessVehicles(conn=conn)
AccessSessions = AccessSessions(conn=conn)
AccessPayments = AccessPayments(conn=conn)
AccessReservations = AccessReservations(conn=conn)



user = User(id=1,
            username="thomas",
            name="ardy",
            email="thomas@gmail.com",
            password="1234",
            created_at=datetime(year=2025, month=11, day=19),
            phone="0612107356",
            role="ADMIN",
            birth_year=2003,
            active=True)
parking_lot = ParkingLot(id=None,
                         name="ardy",
                         location="ardy",
                         address="ardy",
                         capacity=1,
                         reserved=1,
                         tariff=1.0,
                         daytariff=1.0,
                         coordinates=ParkingLotCoordinates(id=None, lng=1.0, lat=1.0),
                         created_at=datetime(year=2025, month=11, day=19))
vehicle = Vehicle(id=None,
                  user=user,
                  licenseplate="000",
                  model="ardy",
                  make="ardy",
                  color="red",
                  year=2003,
                  created_at=datetime(year=2025, month=11, day=19))
payments = AccessReservations.get_reservations_by_userid(user_id=281)


print(payments)

conn.close_connection()

