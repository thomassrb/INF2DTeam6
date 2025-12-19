from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any
import logging
import sqlite3
import json
from ..Models.DiscountCode import DiscountCode

logger = logging.getLogger(__name__)

class AccessDiscountCodes:
    def __init__(self, connection):
        """Initialize with either a database connection, cursor, or DBConnection."""
        if hasattr(connection, 'connection') and hasattr(connection, 'cursor'):
            self.connection = connection.connection
            self.cursor = connection.cursor
            self._owns_cursor = True
        elif isinstance(connection, sqlite3.Connection):
            self.connection = connection
            self.cursor = connection.cursor()
            self._owns_cursor = True
        elif isinstance(connection, sqlite3.Cursor):
            self.cursor = connection
            self.connection = connection.connection
            self._owns_cursor = False
        else:
            raise ValueError(
                "connection must be a sqlite3.Connection, sqlite3.Cursor, or DBConnection"
            )
            
        self._create_tables()

    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS discount_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            discount_percentage INTEGER NOT NULL,
            max_uses INTEGER,
            uses INTEGER DEFAULT 0,
            valid_from TIMESTAMP,
            valid_until TIMESTAMP,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            location_rules TEXT,
            time_rules TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
        """)
        
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS discount_code_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            amount_before_discount REAL NOT NULL,
            discount_amount REAL NOT NULL,
            used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (code_id) REFERENCES discount_codes(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """)
        self.connection.commit()

    def __del__(self):
        """Clean up the cursor if we own it"""
        if hasattr(self, '_owns_cursor') and self._owns_cursor and self.cursor:
            self.cursor.close()

    def _row_to_dict(self, row) -> Optional[Dict[str, Any]]:
        """Convert a database row to a dictionary"""
        if not row:
            return None
            
        result = {key: row[key] for key in row.keys()}
        
        for field in ['location_rules', 'time_rules']:
            if field in result and result[field] is not None:
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    result[field] = None
                    
        return result

    def get_discount_code_by_id(self, code_id: int) -> Optional[Dict[str, Any]]:
        """Get a discount code by its ID"""
        self.cursor.execute("SELECT * FROM discount_codes WHERE id = ?", (code_id,))
        return self._row_to_dict(self.cursor.fetchone())

    def get_discount_code_by_code(self, code: str) -> Optional[Dict[str, Any]]:
        """Get a discount code by its code"""
        self.cursor.execute("SELECT * FROM discount_codes WHERE code = ?", (code.upper(),))
        return self._row_to_dict(self.cursor.fetchone())

    def create_discount_code(self, code_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new discount code"""
        try:
            if 'code' not in code_data or not code_data['code']:
                code = DiscountCode.generate_code()
            else:
                code = code_data['code']

            self.cursor.execute(
                """
                INSERT INTO discount_codes 
                (code, discount_percentage, max_uses, valid_from, valid_until, 
                 created_by, is_active, location_rules, time_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING *
                """,
                (
                    code.upper(),
                    code_data['discount_percentage'],
                    code_data.get('max_uses'),
                    code_data.get('valid_from'),
                    code_data.get('valid_until'),
                    code_data.get('created_by'),
                    int(code_data.get('is_active', True)),
                    json.dumps(code_data.get('location_rules')) if code_data.get('location_rules') else None,
                    json.dumps(code_data.get('time_rules')) if code_data.get('time_rules') else None
                )
            )
            result = self._row_to_dict(self.cursor.fetchone())
            self.connection.commit()
            return result
        except sqlite3.IntegrityError as e:
            self.connection.rollback()
            if "UNIQUE constraint failed" in str(e):
                raise ValueError("A discount code with this code already exists")
            raise
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error creating discount code: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to create discount code: {str(e)}")

    def get_all_discount_codes(self) -> List[Dict[str, Any]]:
        """Get all discount codes"""
        self.cursor.execute("SELECT * FROM discount_codes ORDER BY created_at DESC")
        return [self._row_to_dict(row) for row in self.cursor.fetchall()]

    def update_discount_code(self, code_id: int, **updates) -> Optional[Dict[str, Any]]:
        """Update a discount code"""
        if not updates:
            return None

        if 'location_rules' in updates:
            updates['location_rules'] = json.dumps(updates['location_rules']) if updates['location_rules'] else None
        if 'time_rules' in updates:
            updates['time_rules'] = json.dumps(updates['time_rules']) if updates['time_rules'] else None

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values())
        values.append(code_id)
        
        try:
            self.cursor.execute(
                f"UPDATE discount_codes SET {set_clause} WHERE id = ? RETURNING *",
                values
            )
            result = self._row_to_dict(self.cursor.fetchone())
            self.connection.commit()
            return result
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error updating discount code: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to update discount code: {str(e)}")

    def delete_discount_code(self, code_id: int) -> bool:
        """Delete a discount code"""
        try:
            self.cursor.execute("DELETE FROM discount_codes WHERE id = ?", (code_id,))
            self.connection.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error deleting discount code: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to delete discount code: {str(e)}")

    def apply_discount_code(self, code: str, user_id: int, amount: float) -> Tuple[float, str]:
        """
        Apply a discount code to an amount
        
        Args:
            code: The discount code to apply
            user_id: ID of the user applying the code
            amount: Original amount before discount
            
        Returns:
            Tuple of (final_amount, message)
        """
        try:
            self.cursor.execute(
                """
                SELECT * FROM discount_codes 
                WHERE code = ? AND is_active = 1 
                AND (valid_until IS NULL OR valid_until >= ?)
                AND (max_uses IS NULL OR uses < max_uses)
                """,
                (code.upper(), datetime.now().isoformat())
            )
            discount = self._row_to_dict(self.cursor.fetchone())
            
            if not discount:
                return amount, "Invalid or expired discount code"
                
            if discount['max_uses'] is not None and discount['uses'] >= discount['max_uses']:
                return amount, "This discount code has reached its maximum usage limit"
                
            if discount.get('location_rules'):
                pass
                
            if discount.get('time_rules'):
                pass
                
            discount_amount = (amount * discount['discount_percentage']) / 100
            final_amount = max(0, amount - discount_amount)
            
            self.cursor.execute(
                """
                UPDATE discount_codes 
                SET uses = uses + 1 
                WHERE id = ?
                """,
                (discount['id'],)
            )
            
            self.cursor.execute(
                """
                INSERT INTO discount_code_usage 
                (code_id, user_id, amount_before_discount, discount_amount)
                VALUES (?, ?, ?, ?)
                """,
                (discount['id'], user_id, amount, discount_amount)
            )
            
            if discount['max_uses'] is not None and (discount['uses'] + 1) >= discount['max_uses']:
                self.cursor.execute(
                    "UPDATE discount_codes SET is_active = 0 WHERE id = ?",
                    (discount['id'],)
                )
            
            self.connection.commit()
            return final_amount, f"{discount['discount_percentage']}% discount applied"
            
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error applying discount code: {str(e)}", exc_info=True)
            return amount, f"Error applying discount code: {str(e)}"