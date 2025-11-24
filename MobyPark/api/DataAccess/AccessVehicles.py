import sqlite3
from DBConnection import DBConnection
from datetime import datetime
from .AccessUsers import AccessUsers
from Models.Vehicle import Vehicle

class AccessVehicles:

    def __init__(self, conn: DBConnection):
        self.cursor = conn.cursor
        self.conn = conn.connection
        self.accessusers = AccessUsers(conn=conn)


    def get_vehicle(self, id):
        query = """
        SELECT * FROM vehicles
        WHERE id = ?;
        """
        self.cursor.execute(query, [id])
        vehicle = self.cursor.fetchone()
        if vehicle is None:
            return None
        else:
            vehicle_dict = dict(vehicle)
            vehicle_dict["created_at"] = datetime.strptime(vehicle_dict["created_at"], "%Y-%m-%d %H:%M:%S")
            vehicle_dict["user"] = self.accessusers.get_user_byid(id=vehicle_dict["user_id"])
            del vehicle_dict["user_id"]
            return Vehicle(**vehicle_dict)


    def add_vehicle(self, vehicle: Vehicle):
        query = """
        INSERT INTO vehicles
            (user_id, licenseplate, make, model, color, year, created_at)
        VALUES
            (:user_id, :licenseplate, :make, :model, :color, :year, :created_at)
        RETURNING id;
        """
        vehicle_dict = vehicle.__dict__
        vehicle_dict["user_id"] = vehicle.user.id

        try:
            self.cursor.execute(query, vehicle_dict)
            vehicle.id = self.cursor.fetchone()[0]
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def update_vehicle(self, vehicle):
        query = """
        UPDATE vehicles
        SET licenseplate = :licenseplate,
            make = :make,
            model = :model,
            color = :color,
            year = :year,
            created_at = :created_at
        WHERE id = :id
        """
        try:
            self.cursor.execute(query, vehicle.__dict__)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)
            

    def delete_vehicle(self, vehicle):
        query = """
        DELETE FROM vehicles
        WHERE id = :id;
        """
        self.cursor.execute(query, vehicle.__dict__)
        self.conn.commit()
