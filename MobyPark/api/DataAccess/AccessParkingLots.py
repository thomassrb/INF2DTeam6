import sqlite3
import math
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.ParkingLotCoordinates import ParkingLotCoordinates

def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance between two points 
    on the earth specified in decimal degrees.
    Returns distance in meters.
    """
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    meters = 6371 * c * 1000
    return round(meters, 2)

class AccessParkingLots:

    def __init__(self, conn):
        self.cursor = conn.cursor
        self.conn = conn.connection


<<<<<<< HEAD
    def get_all_parking_lots(self, lat: float = None, lng: float = None, radius: float = None) -> List[Dict[str, Any]]:
        """
        Get all parking lots, optionally filtered by distance from a point.
        
        Args:
            lat: Latitude of the center point
            lng: Longitude of the center point
            radius: Maximum distance in meters from the center point
            
        Returns:
            List of parking lots with distance if location is provided
        """
        try:
            query = """
            SELECT p.*, c.lat, c.lng
            FROM parking_lots p
            LEFT JOIN parking_lots_coordinates c ON c.id = p.id;
            """
            self.cursor.execute(query)
            parking_lots = self.cursor.fetchall()
            
            if not parking_lots:
                return []
                
            result = []
            for row in parking_lots:
                row_dict = dict(row)
                parking_lot = {
                    "id": str(row_dict["id"]),
                    "name": row_dict.get("name", ""),
                    "location": row_dict.get("location", ""),
                    "address": row_dict.get("address", ""),
                    "capacity": int(row_dict.get("capacity", 0)),
                    "reserved": int(row_dict.get("reserved", 0)),
                    "tariff": float(row_dict.get("tariff", 0.0)),
                    "daytariff": float(row_dict.get("daytariff", 0.0)),
                    "coordinates": [
                        float(row_dict.get("lat", 0.0)), 
                        float(row_dict.get("lng", 0.0))
                    ],
                    "created_at": row_dict.get("created_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                if lat is not None and lng is not None and 'coordinates' in parking_lot:
                    lot_lat = parking_lot['coordinates'][0]
                    lot_lng = parking_lot['coordinates'][1]
                    if lot_lat is not None and lot_lng is not None:
                        distance = haversine(lat, lng, lot_lat, lot_lng)
                        parking_lot['distance'] = distance
                
                result.append(parking_lot)
            
            if lat is not None and lng is not None and radius is not None:
                result = [lot for lot in result if 'distance' in lot and lot['distance'] <= radius]
            
            if lat is not None and lng is not None:
                result = sorted(result, key=lambda x: x.get('distance', float('inf')))
            
            if lat is not None and lng is not None and len(result) > 5:
                result = result[:5]
                
            return result
            
        except Exception as e:
            print(f"Error in get_all_parking_lots: {str(e)}")
            raise
=======
    def get_all_parking_lots(self):
        query = """
        SELECT id FROM parking_lots;
        """
        self.cursor.execute(query)
        parking_lot_ids = self.cursor.fetchall()
        parking_lots = list(map(lambda id: self.get_parking_lot(id=id["id"]), parking_lot_ids))

        return parking_lots
>>>>>>> nieuw_intergration_test
    
    
    def get_parking_lot(self, lot_id: str):
        try:
            if not lot_id:
                return None
                
            query = """
            SELECT p.*, c.lat, c.lng
            FROM parking_lots p
            LEFT JOIN parking_lots_coordinates c ON c.id = p.id
            WHERE p.id = ?;
            """
            self.cursor.execute(query, [str(lot_id)])
            result = self.cursor.fetchone()
            
            if not result:
                return None
                
            row_dict = dict(result)
            return {
                "id": str(row_dict["id"]),
                "name": row_dict.get("name", ""),
                "location": row_dict.get("location", ""),
                "address": row_dict.get("address", ""),
                "capacity": int(row_dict.get("capacity", 0)),
                "reserved": int(row_dict.get("reserved", 0)),
                "tariff": float(row_dict.get("tariff", 0.0)),
                "daytariff": float(row_dict.get("daytariff", 0.0)),
                "coordinates": [
                    float(row_dict.get("lat", 0.0)), 
                    float(row_dict.get("lng", 0.0))
                ],
                "created_at": row_dict.get("created_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        except Exception as e:
            print(f"Error in get_parking_lot for id {lot_id}: {str(e)}")
            raise


    def delete_parking_lot(self, parkinglot: ParkingLot):
        query = """
        DELETE FROM parking_lots
        WHERE id = :id;
        """
        coordinate_query = """ 
        DELETE FROM parking_lots_coordinates
        WHERE id = :id;
        """
        try:
            self.cursor.execute(coordinate_query, parkinglot.__dict__)
            self.cursor.execute(query, parkinglot.__dict__)
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


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
            return True
        except sqlite3.IntegrityError as e:
            return False


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

