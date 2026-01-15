import sqlite3
from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.Models.Session import Session
from MobyPark.api.Models.User import User
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.Vehicle import Vehicle
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.DataAccess.AccessParkingLots import AccessParkingLots
from MobyPark.api.DataAccess.AccessVehicles import AccessVehicles
from datetime import datetime

class AccessSessions:

    def __init__(self, conn: DBConnection):
        self.cursor = conn.cursor
        self.conn = conn.connection
        self.accessusers = AccessUsers(conn=conn)
        self.accessparkinglots = AccessParkingLots(conn=conn)
        self.accessvehicles = AccessVehicles(conn=conn)


    def get_session(self, id):
        query = """
        SELECT * FROM sessions
        WHERE id = ?;
        """
        self.cursor.execute(query, [id])
        session = self.cursor.fetchone()

        if session is None:
            return None

        session_dict = dict(session)
        session_dict["started"] = datetime.strptime(session_dict["started"], "%Y-%m-%d %H:%M:%S")
        session_dict["stopped"] = datetime.strptime(session_dict["stopped"], "%Y-%m-%d %H:%M:%S")
        session_dict["user"] = self.accessusers.get_user_byid(id=session_dict["user_id"])
        session_dict["vehicle"] = self.accessvehicles.get_vehicle(session_dict["vehicle_id"])
        session_dict["parking_lot"] = self.accessparkinglots.get_parking_lot(session_dict["parking_lot_id"])

        del session_dict["user_id"]
        del session_dict["parking_lot_id"]
        del session_dict["vehicle_id"]

        return Session(**session_dict)
    

    def get_sessions_byuser(self, user: User):
        query = """
        SELECT id FROM sessions
        WHERE user_id = ?;
        """
        self.cursor.execute(query, [user.id])
        ids = self.cursor.fetchall()
        sessions = list(map(lambda id: self.get_session(id=id["id"]), ids))

        return sessions


    def get_pending_session_bylicenseplate(self, licenseplate: str):
        query = """
        SELECT id FROM sessions
        WHERE payment_status = ?
        AND licenseplate = ?;
        """
        self.cursor.execute(query, ["pending", licenseplate])
        id = self.cursor.fetchone()

        return self.get_session(id=id["id"])
    

    def add_session(self, session: Session):
        query = """
        INSERT INTO sessions
            (parking_lot_id, vehicle_id, started, stopped, username, user_id, duration_minutes, cost, payment_status)
        VALUES
            (:parking_lot_id, :vehicle_id, :started, :stopped, :username, :user_id, :duration_minutes, :cost, :payment_status)
        RETURNING id;
        """
        session_dict = session.__dict__
        session_dict["parking_lot_id"] = session_dict["parking_lot"].id
        session_dict["vehicle_id"] = session_dict["vehicle"].id
        session_dict["user_id"] = session_dict["user"].id
        try:
            self.cursor.execute(query, session_dict)
            session.id = self.cursor.fetchone()[0]
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)

        
    def update_session(self, session: Session):
        query = """
        UPDATE sessions
        SET parking_lot_id = :parking_lot_id,
            vehicle_id = :vehicle_id,
            started = :started,
            stopped = :stopped,
            username = :username,
            user_id = :user_id,
            duration_minutes = :duration_minutes,
            cost = :cost,
            payment_status = :payment_status
        """
        session_dict = session.__dict__
        session_dict["parking_lot_id"] = session_dict["parking_lot"].id
        session_dict["vehicle_id"] = session_dict["vehicle"].id
        session_dict["user_id"] = session_dict["user"].id
        try:
            self.cursor.execute(query, session_dict)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def delete_session(self, session: Session):
        query = """
        DELETE FROM sessions
        WHERE id = :id;
        """
        self.cursor.execute(query, session.__dict__)
        self.conn.commit()