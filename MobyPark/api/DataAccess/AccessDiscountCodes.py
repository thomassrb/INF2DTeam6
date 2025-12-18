import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from ..Models.DiscountCode import DiscountCode, LocationRule, TimeRule

logger = logging.getLogger(__name__)

class AccessDiscountCodes:
    def __init__(self, db_path: str = "database.db", connection=None):
        """
        Initialize the AccessDiscountCodes instance.
        
        Args:
            db_path: Path to the SQLite database file
            connection: Either a sqlite3.Connection or a cursor with a connection
        """
    self.connection = None
    self.cursor = None
    self._owns_connection = False
    
    try:
        if connection:
            # If a connection or cursor is provided, use it
            if hasattr(connection, 'execute'):
                # It's a cursor
                self.cursor = connection
                self.connection = connection.connection
            elif hasattr(connection, 'cursor'):
                # It's a connection
                self.connection = connection
                self.cursor = connection.cursor()
            else:
                raise ValueError("connection must be a sqlite3.Connection or a cursor")
        else:
            self.connection = sqlite3.connect(db_path)
            self.cursor = self.connection.cursor()
            self._owns_connection = True
            
        # Configure the connection
        self.connection.row_factory = sqlite3.Row
        self._create_tables()
            
    except Exception as e:
        if self._owns_connection and self.connection:
            self.connection.close()
        logger.error(f"Failed to initialize database connection: {e}")
        raise

    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        try:
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
            
            self.cursor.execute("PRAGMA table_info(discount_codes)")
            columns = [column[1] for column in self.cursor.fetchall()]
            
            if 'location_rules' not in columns:
                logger.info("Adding missing column: location_rules")
                self.cursor.execute("ALTER TABLE discount_codes ADD COLUMN location_rules TEXT")
            
            if 'time_rules' not in columns:
                logger.info("Adding missing column: time_rules")
                self.cursor.execute("ALTER TABLE discount_codes ADD COLUMN time_rules TEXT")
            
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
            logger.info("Database tables created/verified successfully")
            
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error creating database tables: {str(e)}")
            raise

    def add_discount_code(self, discount_code: DiscountCode) -> Optional[Dict]:
        """Add a new discount code to the database"""
        try:
            location_rules = None
            if discount_code.location_rules is not None:
                if hasattr(discount_code.location_rules, 'dict'):
                    location_rules = json.dumps(discount_code.location_rules.dict())
                else:
                    location_rules = json.dumps(discount_code.location_rules)
                    
            time_rules = None
            if discount_code.time_rules is not None:
                if hasattr(discount_code.time_rules, 'dict'):
                    time_rules = json.dumps(discount_code.time_rules.dict())
                else:
                    time_rules = json.dumps(discount_code.time_rules)
            
            valid_from = (discount_code.valid_from.isoformat() 
                         if discount_code.valid_from else None)
            valid_until = (discount_code.valid_until.isoformat() 
                          if discount_code.valid_until else None)
            
            self.cursor.execute(
                """
                INSERT INTO discount_codes 
                (code, discount_percentage, max_uses, uses,
                 valid_from, valid_until, created_by, is_active,
                 location_rules, time_rules)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING *
                """,
                (discount_code.code.upper() if discount_code.code else None,
                 discount_code.discount_percentage,
                 discount_code.max_uses,
                 getattr(discount_code, 'uses', 0),
                 valid_from,
                 valid_until,
                 discount_code.created_by,
                 int(getattr(discount_code, 'is_active', True)),
                 location_rules,
                 time_rules)
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

    def get_discount_code(self, code_id: int) -> Optional[Dict]:
        """Get a discount code by ID"""
        self.cursor.execute("SELECT * FROM discount_codes WHERE id = ?", (code_id,))
        return self._row_to_dict(self.cursor.fetchone())

    def get_discount_code_by_code(self, code: str) -> Optional[Dict]:
        """Get a discount code by code"""
        self.cursor.execute("SELECT * FROM discount_codes WHERE code = ?", (code.upper(),))
        return self._row_to_dict(self.cursor.fetchone())

    def get_all_discount_codes(self, include_inactive: bool = False) -> List[Dict]:
        """Get all discount codes, optionally including inactive ones"""
        query = "SELECT * FROM discount_codes"
        params = ()
        
        if not include_inactive:
            query += " WHERE is_active = 1"
            
        query += " ORDER BY created_at DESC"
        self.cursor.execute(query, params)
        return [self._row_to_dict(row) for row in self.cursor.fetchall()]

    def update_discount_code(self, code_id: int, updates: Dict) -> Optional[Dict]:
        """Update a discount code"""
        try:
            if 'location_rules' in updates and updates['location_rules'] is not None:
                if hasattr(updates['location_rules'], 'dict'):
                    updates['location_rules'] = json.dumps(updates['location_rules'].dict())
                else:
                    updates['location_rules'] = json.dumps(updates['location_rules'])
            
            if 'time_rules' in updates and updates['time_rules'] is not None:
                if hasattr(updates['time_rules'], 'dict'):
                    updates['time_rules'] = json.dumps(updates['time_rules'].dict())
                else:
                    updates['time_rules'] = json.dumps(updates['time_rules'])
            
            if 'valid_from' in updates and updates['valid_from'] is not None:
                updates['valid_from'] = updates['valid_from'].isoformat()
            
            if 'valid_until' in updates and updates['valid_until'] is not None:
                updates['valid_until'] = updates['valid_until'].isoformat()
            
            set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
            values = list(updates.values())
            values.append(code_id)
            
            query = f"UPDATE discount_codes SET {set_clause} WHERE id = ? RETURNING *"
            
            self.cursor.execute(query, values)
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
        """Apply a discount code to an amount"""
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
                
            discount_amount = (amount * discount['discount_percentage']) / 100
            final_amount = max(0, amount - discount_amount)
            
            self.cursor.execute(
                """
                UPDATE discount_codes 
                SET uses = uses + 1 
                WHERE id = ?
                RETURNING uses
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
            
            self.connection.commit()
            return final_amount, f"{discount['discount_percentage']}% discount applied"
            
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error applying discount code: {str(e)}", exc_info=True)
            return amount, f"Error applying discount code: {str(e)}"

    def get_discount_code_usage(self, code_id: int) -> List[Dict]:
        """Get usage history for a discount code"""
        self.cursor.execute(
            """
            SELECT u.username, dcu.amount_before_discount, dcu.discount_amount, dcu.used_at
            FROM discount_code_usage dcu
            JOIN users u ON dcu.user_id = u.id
            WHERE dcu.code_id = ?
            ORDER BY dcu.used_at DESC
            """,
            (code_id,)
        )
        return [dict(row) for row in self.cursor.fetchall()]

    def _row_to_dict(self, row) -> Optional[Dict[str, Any]]:
        """Convert a database row to a dictionary"""
        if not row:
            return None
            
        columns = [column[0] for column in self.cursor.description]
        
        result = dict(zip(columns, row))
        
        for field in ['location_rules', 'time_rules']:
            if field in result and result[field]:
                try:
                    if isinstance(result[field], str):
                        result[field] = json.loads(result[field])
                except json.JSONDecodeError:
                    logger.warning(f"Error decoding {field}: {result[field]}")
                    result[field] = None
                except Exception as e:
                    logger.error(f"Unexpected error with {field}: {str(e)}")
                    result[field] = None
                    
        for field in ['valid_from', 'valid_until', 'created_at']:
            if field in result and result[field]:
                if isinstance(result[field], str):
                    try:
                        result[field] = datetime.fromisoformat(result[field].replace('Z', '+00:00'))
                    except ValueError:
                        logger.warning(f"Error parsing {field} date: {result[field]}")
                        result[field] = None
                        
        if 'is_active' in result and isinstance(result['is_active'], int):
            result['is_active'] = bool(result['is_active'])
            
        return result

    def __del__(self):
        """Ensure the database connection is closed when the object is destroyed"""
        if (hasattr(self, '_owns_connection') and 
            self._owns_connection and 
            hasattr(self, 'connection') and 
            self.connection is not None):
            try:
                self.connection.close()
                logger.debug("Database connection closed")
            except Exception as e:
                logger.warning(f"Error closing database connection: {e}")