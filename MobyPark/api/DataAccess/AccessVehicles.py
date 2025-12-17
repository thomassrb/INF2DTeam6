import sqlite3
from MobyPark.api.DBConnection import DBConnection
from datetime import datetime
from MobyPark.api.DataAccess.AccessUsers import AccessUsers
from MobyPark.api.Models.Vehicle import Vehicle
from MobyPark.api.Models.User import User
from MobyPark.api import crypto_utils

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

            # decrypt licenseplate
            try:
                vehicle_dict["licenseplate"] = crypto_utils.decrypt_str(vehicle_dict.get("licenseplate"))
            except Exception:
                pass
            vehicle_dict["user"] = self.accessusers.get_user_byid(id=vehicle_dict["user_id"])
            del vehicle_dict["user_id"]
            return Vehicle(**vehicle_dict)
        

    def get_vehicles_byuser(self, user: User):
        query = """
        SELECT id FROM users
        WHERE user_id = ?;
        """
        self.cursor.execute(query, [user.id])
        vehicle_ids = self.cursor.fetchall()
        vehicles = list(map(lambda id: self.get_vehicle(id=id["id"]), vehicle_ids))

        return vehicles
        

    def get_all_vehicles(self):
        query = """"
        SELECT * FROM vehicles
        """
        self.cursor.execute(query)
        vehicles = self.cursor.fetchall()

        return vehicles


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

        # encrypt licenseplate
        try:
            vehicle_dict["licenseplate"] = crypto_utils.encrypt_str(vehicle_dict.get("licenseplate"))
        except Exception:
            pass
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
        payload = dict(vehicle.__dict__)
        try:
            payload["licenseplate"] = crypto_utils.encrypt_str(payload.get("licenseplate"))
        except Exception:
            pass
        try:
            self.cursor.execute(query, payload)
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
