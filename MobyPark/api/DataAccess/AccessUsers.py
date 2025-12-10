import sqlite3
from MobyPark.api.DBConnection import DBConnection
from MobyPark.api.Models.User import User
from datetime import datetime

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
        try:
            self.cursor.execute(query, user.__dict__)
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
        try:
            self.cursor.execute(query, user.__dict__)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)
