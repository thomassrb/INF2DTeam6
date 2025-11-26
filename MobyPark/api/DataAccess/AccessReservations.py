import sqlite3
from DBConnection import DBConnection
from Models.Reservation import Reservation
from DataAccess.AccessUsers import AccessUsers
from DataAccess.AccessVehicles import AccessVehicles
from DataAccess.AccessParkingLots import AccessParkingLots
from datetime import datetime

class AccessReservations:

    def __init__(self, conn: DBConnection):
        self.cursor = conn.cursor
        self.conn = conn.connection
        self.accessvehicles = AccessVehicles(conn=conn)
        self.accessusers = AccessUsers(conn=conn)
        self.accessparkinglots = AccessParkingLots(conn=conn)


    def get_reservation(self, id: str):
        query = """
        SELECT * FROM reservations
        WHERE id = ?;
        """
        self.cursor.execute(query, [id])
        reservation = self.cursor.fetchone()

        if reservation is None:
            return None
        
        reservation_dict = dict(reservation)
        reservation_dict["start_time"] = datetime.strptime(reservation_dict["start_time"], "%Y-%m-%d %H:%M:%S")
        reservation_dict["end_time"] = datetime.strptime(reservation_dict["end_time"], "%Y-%m-%d %H:%M:%S")
        reservation_dict["created_at"] = datetime.strptime(reservation_dict["created_at"], "%Y-%m-%d %H:%M:%S")

        reservation_dict["user"] = self.accessusers.get_user_byid(id=reservation_dict["user_id"])
        reservation_dict["vehicle"] = self.accessvehicles.get_vehicle(id=reservation_dict["vehicle_id"])
        reservation_dict["parking_lot"] = self.accessparkinglots.get_parking_lot(id=reservation_dict["parking_lot_id"])

        del reservation_dict["user_id"]
        del reservation_dict["vehicle_id"]
        del reservation_dict["parking_lot_id"]

        return Reservation(**reservation_dict)


    def get_reservations_by_userid(self, user_id:int) -> list[Reservation]:
        query = """
        SELECT id FROM reservations
        WHERE user_id = ?;
        """
        self.cursor.execute(query, [user_id])
        ids = self.cursor.fetchall()
        reservations = list(map(lambda id: self.get_reservation(id["id"]), ids))

        return reservations
    

    def add_reservation(self, reservation: Reservation):
        query = """"
        INSERT INTO reservations
            (user_id, parking_lot_id, vehicle_id, start_time, end_time, status, created_at, cost)
        VALUES
            (:user_id, :parking_lot_id, :vehicle_id, :start_time, :end_time, :status, :created_at, :cost)
        RETURNING id;
        """
        reservation_dict = reservation.__dict__
        reservation_dict["user_id"] = reservation.user.id
        reservation_dict["parking_lot_id"] = reservation.parking_lot.id
        reservation_dict["vehicle_id"] = reservation.vehicle.id

        try:
            self.cursor.execute(query, reservation_dict)
            reservation.id = self.cursor.fetchone()[0]
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def update_reservation(self, reservation: Reservation):
        query = """
        UPDATE reservations
        SET user_id = :user_id,
            parking_lot_id = :parking_lot_id,
            vehicle_id = :vehicle_id,
            start_time = :start_time,
            end_time = :end_time,
            status = :status,
            created_at = :created_at,
            cost = :cost
        WHERE id = :id;
        """
        reservation_dict = reservation.__dict__
        reservation_dict["user_id"] = reservation.user.id
        reservation_dict["parking_lot_id"] = reservation.parking_lot.id
        reservation_dict["vehicle_id"] = reservation.vehicle.id

        try:
            self.cursor.execute(query, reservation_dict)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)



    def delete_reservation(self, reservation: Reservation):
        query = """
        DELETE FROM reservations
        WHERE id = :id;
        """
        self.cursor.execute(query, reservation.__dict__)
        self.conn.commit()
        