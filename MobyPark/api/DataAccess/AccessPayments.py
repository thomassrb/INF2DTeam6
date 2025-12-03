import sqlite3
from DBConnection import DBConnection
from Models.Payment import Payment
from Models.TransanctionData import TransactionData
from Models.User import User
from DataAccess.AccessUsers import AccessUsers
from DataAccess.AccessParkingLots import AccessParkingLots
from DataAccess.AccessSessions import AccessSessions
from datetime import datetime

class AccessPayments:

    def __init__(self, conn: DBConnection):
        self.cursor = conn.cursor
        self.conn = conn.connection
        self.accessusers = AccessUsers(conn=conn)
        self.accessparkinglots = AccessParkingLots(conn=conn)
        self.accesssessions = AccessSessions(conn=conn)


    def get_payment(self, id: str):
        query = """
        SELECT * FROM payments
        WHERE id = ?;
        """
        tdata_query = """
        SELECT * FROM t_data
        WHERE id = ?;
        """
        self.cursor.execute(query, [id])
        payment = self.cursor.fetchone()
        self.cursor.execute(tdata_query, [id])
        tdata = self.cursor.fetchone()

        if payment is None or tdata is None:
            return None
        
        payment_dict = dict(payment)
        tdata_dict = dict(tdata)
        payment_dict["created_at"] = datetime.strptime(payment_dict["created_at"], "%Y-%m-%d %H:%M:%S")
        payment_dict["completed"] = datetime.strptime(payment_dict["completed"], "%Y-%m-%d %H:%M:%S")
        tdata_dict["date"] = datetime.strptime(tdata_dict["date"], "%Y-%m-%d %H:%M:%S")

        payment_dict["user"] = self.accessusers.get_user_byid(id=payment_dict["user_id"])
        payment_dict["session"] = self.accesssessions.get_session(id=payment_dict["session_id"])
        payment_dict["parking_lot"] = self.accessparkinglots.get_parking_lot(id=payment_dict["parking_lot_id"])
        payment_dict["t_data"] = TransactionData(**tdata_dict)

        del payment_dict["user_id"]
        del payment_dict["session_id"]
        del payment_dict["parking_lot_id"]

        return Payment(**payment_dict)
    

    def get_all_payments(self):
        query = """"
        SELECT p.*, t.* FROM payments p
        JOIN t_data t ON t.id = p.id;
        """
        self.cursor.execute(query)
        payments = self.cursor.fetchall()

        return payments


    def get_payments_by_user(self, user:User) -> list[Payment]:
        query = """
        SELECT id FROM payments
        WHERE user_id = ?;
        """
        self.cursor.execute(query, [user.id])
        ids = self.cursor.fetchall()
        payments = list(map(lambda id: self.get_payment(id["id"]), ids))

        return payments
    
    
    def add_payment(self, payment: Payment):
        query = """
        INSERT INTO payments
            (id, amount, initiator, user_id, created_at, completed, hash, session_id, parking_lot_id)
        VALUES
            (:id, :amount, :initiator, :user_id, :created_at, :completed, :hash, :session_id, :parking_lot_id);
        """
        tdata_query = """
        INSERT INTO t_data
            (id, amount, date, method, issuer, bank)
        VALUES
            (:id, :amount, :date, :method, :issuer, :bank);
        """
        payment_dict = payment.__dict__
        payment_dict["user_id"] = payment.user.id
        payment_dict["session_id"] = payment.session.id
        payment_dict["parking_lot_id"] = payment.parking_lot.id
        
        try:
            self.cursor.execute(query, payment_dict)
            self.cursor.execute(tdata_query, payment.t_data.__dict__)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def update_payment(self, payment: Payment):
        query = """
        UPDATE payments
        SET amount = :amount,
            initiator = :initiator,
            user_id = user_id,
            created_at = :created_at,
            hash = :hash,
            session_id = session_id
            parking_lot_id = :parking_lot_id
        WHERE id = :id;
        """
        tdata_query = """
        UPDATE t_data
        SET amount = :amount,
            date = :date,
            method = :method,
            issuer = :issuer,
            bank = :bank
        WHERE id = :id;
        """
        payment_dict = payment.__dict__
        payment_dict["parking_lot_id"] = payment.parking_lot.id
        payment_dict["user_id"] = payment.user.id
        payment_dict["session_id"] = payment.session.id

        try:
            self.cursor.execute(query, payment_dict)
            self.cursor.execute(tdata_query, payment.t_data.__dict__)
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def delete_payment(self, payment: Payment):
        query = """
        DELETE FROM payments
        WHERE id = :id;
        """
        coordinate_query = """ 
        DELETE FROM t_data
        WHERE id = :id;
        """
        self.cursor.execute(query, payment.__dict__)
        self.cursor.execute(coordinate_query, payment.__dict__)
        self.conn.commit()