from ..Models.FreeParking import FreeParking
from datetime import datetime
from typing import Optional, List

class AccessFreeParking:
    def __init__(self, connection):
        self.connection = connection.connection
        self.cursor = self.connection.cursor()

    def add_free_parking_plate(self, license_plate: str, added_by: int) -> FreeParking:
        """Add a license plate to the free parking whitelist"""
        try:
            self.cursor.execute(
                "INSERT INTO free_parking_plates (license_plate, added_by) VALUES (?, ?)",
                (license_plate.upper(), added_by)
            )
            self.connection.commit()
            
            return self.get_free_parking_by_plate(license_plate)
        except Exception as e:
            self.connection.rollback()
            if "UNIQUE constraint failed" in str(e):
                raise ValueError(f"License plate {license_plate} is already in the free parking list")
            raise

    def get_free_parking_by_plate(self, license_plate: str) -> Optional[FreeParking]:
        """Get free parking record by license plate"""
        self.cursor.execute(
            "SELECT * FROM free_parking_plates WHERE license_plate = ?",
            (license_plate.upper(),)
        )
        row = self.cursor.fetchone()
        if row:
            created_at = datetime.fromisoformat(row['created_at']) if row['created_at'] else None
            return FreeParking(
                id=row['id'],
                license_plate=row['license_plate'],
                added_by=row['added_by'],
                created_at=created_at
            )
        return None

    def is_plate_free_parking(self, license_plate: str) -> bool:
        """Check if a license plate is in the free parking whitelist"""
        return self.get_free_parking_by_plate(license_plate) is not None

    def remove_free_parking_plate(self, license_plate: str) -> bool:
        """Remove a license plate from the free parking whitelist"""
        self.cursor.execute(
            "DELETE FROM free_parking_plates WHERE license_plate = ?",
            (license_plate.upper(),)
        )
        self.connection.commit()
        return self.cursor.rowcount > 0

    def get_all_free_parking_plates(self) -> List[FreeParking]:
        """Get all license plates in the free parking whitelist"""
        self.cursor.execute("SELECT * FROM free_parking_plates ORDER BY created_at DESC")
        result = []
        for row in self.cursor.fetchall():
            created_at = datetime.fromisoformat(row['created_at']) if row['created_at'] else None
            result.append(
                FreeParking(
                    id=row['id'],
                    license_plate=row['license_plate'],
                    added_by=row['added_by'],
                    created_at=created_at
                )
            )
        return result