import sqlite3
from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.Models.User import User
from datetime import datetime
from MobyPark.api import crypto_utils

class AccessUsers:

    def __init__(self, conn: DBConnection):
        self.cursor = conn.cursor
        self.conn = conn.connection

    
    def get_user_byusername(self, username):
        query = """
        SELECT * FROM users
        WHERE username = ?;
        """
        self.cursor.execute(query, [username])
        result = self.cursor.fetchone()
        if result is None:
            return None
        else:
            result = dict(result)

        # PII decrypt
        try:
            result["name"] = crypto_utils.decrypt_str(result.get("name"))
        except Exception:
            pass
        try:
            result["email"] = crypto_utils.decrypt_str(result.get("email"))
        except Exception:
            pass
        try:
            result["phone"] = crypto_utils.decrypt_str(result.get("phone"))
        except Exception:
            pass
        result["created_at"] = datetime.strptime(result["created_at"], "%Y-%m-%d")
        return User(**result)
        

    def get_user_byid(self, id):
        query = """
        SELECT * FROM users
        WHERE id = ?;
        """
        self.cursor.execute(query, [id])
        result = self.cursor.fetchone()
        if result is None:
            return None
        else:
            result = dict(result)

            # PII decrypt
            try:
                result["name"] = crypto_utils.decrypt_str(result.get("name"))
            except Exception:
                pass
            try:
                result["email"] = crypto_utils.decrypt_str(result.get("email"))
            except Exception:
                pass
            try:
                result["phone"] = crypto_utils.decrypt_str(result.get("phone"))
            except Exception:
                pass
            result["created_at"] = datetime.strptime(result["created_at"], "%Y-%m-%d")
            return User(**result)
        

    def get_all_users(self):
        query = """"
        SELECT * FROM users
        """
        self.cursor.execute(query)
        users = self.cursor.fetchall()

        return users

    
    def add_user(self, user: User):
        query = """
        INSERT INTO users
            (username, name, email, password, created_at, phone, birth_year, role, active)
        VALUES
            (:username, :name, :email, :password, :created_at, :phone, :birth_year, :role, :active)
        RETURNING id;
        """ 
        # payload voorbereiden met encrypted PII
        payload = dict(user.__dict__)
        try:
            payload["name"] = crypto_utils.encrypt_str(payload.get("name"))
        except Exception:
            pass
        try:
            payload["email"] = crypto_utils.encrypt_str(payload.get("email"))
        except Exception:
            pass
        try:
            payload["phone"] = crypto_utils.encrypt_str(payload.get("phone"))
        except Exception:
            pass
        try:
            self.cursor.execute(query, payload)
            user.id = self.cursor.fetchone()[0]
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def delete_user(self, user: User):
        query = """
        DELETE FROM users
        WHERE id = ?;
        """
        self.cursor.execute(query, [user.id])
        self.conn.commit()

    
    def update_user(self, user: User):
        query = """
        UPDATE users
        SET username = :username,
            name = :name,
            email = :email,
            password = :password,
            created_at = :created_at,
            phone = :phone,
            role = :role,
            birth_year = :birth_year,
            active = :active
        WHERE id = :id;
        """
        payload = dict(user.__dict__)
        try:
            payload["name"] = crypto_utils.encrypt_str(payload.get("name"))
        except Exception:
            pass
        try:
            payload["email"] = crypto_utils.encrypt_str(payload.get("email"))
        except Exception:
            pass
        try:
            payload["phone"] = crypto_utils.encrypt_str(payload.get("phone"))
        except Exception:
            pass
        try:
            self.cursor.execute(query, payload)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)
