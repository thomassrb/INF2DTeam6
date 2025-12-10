import sqlite3
from datetime import datetime
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates

class AccessParkingLots:

    def __init__(self, conn):
        self.cursor = conn.cursor
        self.conn = conn.connection


    def get_all_parking_lots(self):
        query = """
        SELECT p.*, c.*
        FROM parking_lots p
        JOIN parking_lots_coordinates c ON c.id = p.id;
        """
        self.cursor.execute(query)
        parking_lots = self.cursor.fetchall()

        return parking_lots
    
    
    def get_parking_lot(self, id):
        query = """
        SELECT * FROM parking_lots
        WHERE id = ?;
        """
        coordinates_query = """
        SELECT * FROM parking_lots_coordinates
        WHERE id = ?;
        """
        self.cursor.execute(query, [id])
        parking_lot = self.cursor.fetchone()
        self.cursor.execute(coordinates_query, [id])
        coordinates = self.cursor.fetchone()

        if parking_lot is None or coordinates is None:
            return None
        else:
            parking_lot = dict(parking_lot)
            parking_lot["created_at"] = datetime.strptime(parking_lot["created_at"], "%Y-%m-%d %H:%M:%S")
            parking_lot["coordinates"] = ParkingLotCoordinates(**coordinates)
            return ParkingLot(**parking_lot)


    def delete_parking_lot(self, parkinglot: ParkingLot):
        query = """
        DELETE FROM parking_lots
        WHERE id = :id;
        """
        coordinate_query = """ 
        DELETE FROM parking_lots_coordinates
        WHERE id = :id;
        """
        self.cursor.execute(query, parkinglot.__dict__)
        self.cursor.execute(coordinate_query, parkinglot.__dict__)
        self.conn.commit()


    def add_parking_lot(self, parkinglot: ParkingLot):
        query = """
        INSERT INTO parking_lots
            (name, location, address, capacity, reserved, tariff, daytariff, created_at)
        VALUES
            (:name, :location, :address, :capacity, :reserved, :tariff, :daytariff, :created_at)
        RETURNING id;
        """
        coordinates_query = """
        INSERT INTO parking_lots_coordinates
            (id, lat, lng)
        VALUES
            (:id, :lat, :lng)
        """
        try:
            self.cursor.execute(query, parkinglot.__dict__)
            id = self.cursor.fetchone()[0]
            parkinglot.id = id
            parkinglot.coordinates.id = id
            self.cursor.execute(coordinates_query, parkinglot.coordinates.__dict__)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def update_parking_lot(self, parkinglot: ParkingLot):
        query = """
        UPDATE parking_lots
        SET name = :name,
            location = :location,
            address = :address,
            capacity = :capacity,
            reserved = :reserved,
            tariff = :tariff,
            daytariff = :daytariff,
            created_at = :created_at
        WHERE id = :id;
        """
        coordinates_query = """
        UPDATE parking_lots_coordinates
        SET lng = :lng,
            lat = :lat
        WHERE id = :id;
        """
        try:
            self.cursor.execute(query, parkinglot.__dict__)
            self.cursor.execute(coordinates_query, parkinglot.coordinates.__dict__)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)

