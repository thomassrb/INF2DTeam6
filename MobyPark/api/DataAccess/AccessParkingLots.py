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
        SELECT p.*, c.lat, c.lng
        FROM parking_lots p
        LEFT JOIN parking_lots_coordinates c ON c.id = p.id;
        """
        self.cursor.execute(query)
        parking_lots = self.cursor.fetchall()
        
        # Convert SQLite Row objects to dictionaries
        result = []
        for row in parking_lots:
            row_dict = dict(row)
            # Ensure all required fields are present with appropriate defaults
            result.append({
                "id": str(row_dict["id"]),
                "name": row_dict.get("name", ""),
                "location": row_dict.get("location", ""),
                "address": row_dict.get("address", ""),
                "capacity": row_dict.get("capacity", 0),
                "reserved": row_dict.get("reserved", 0),
                "tariff": float(row_dict.get("tariff", 0.0)),
                "daytariff": float(row_dict.get("daytariff", 0.0)),
                "coordinates": [float(row_dict.get("lat", 0.0)), float(row_dict.get("lng", 0.0))],
                "created_at": row_dict.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            })
        
        return result
    
    
    def get_parking_lot(self, id: str):
        try:
            query = """
            SELECT p.*, c.lat, c.lng
            FROM parking_lots p
            LEFT JOIN parking_lots_coordinates c ON c.id = p.id
            WHERE p.id = ?;
            """
            self.cursor.execute(query, [id])
            result = self.cursor.fetchone()
            
            if not result:
                return None
                
            row_dict = dict(result)
            return {
                "id": str(row_dict["id"]),
                "name": row_dict.get("name", ""),
                "location": row_dict.get("location", ""),
                "address": row_dict.get("address", ""),
                "capacity": row_dict.get("capacity", 0),
                "reserved": row_dict.get("reserved", 0),
                "tariff": float(row_dict.get("tariff", 0.0)),
                "daytariff": float(row_dict.get("daytariff", 0.0)),
                "coordinates": [float(row_dict.get("lat", 0.0)), float(row_dict.get("lng", 0.0))],
                "created_at": row_dict.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            }
        except Exception as e:
            print(f"Error getting parking lot {id}: {str(e)}")
            return None


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

