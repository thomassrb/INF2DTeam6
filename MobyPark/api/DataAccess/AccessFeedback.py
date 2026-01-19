from ..Models import Feedback
from ..DBConnection import DBConnection
from .AccessParkingLots import AccessParkingLots
from .AccessUsers import AccessUsers
from datetime import datetime

class AccessFeedback:
    def __init__(self, connection: DBConnection):
        self.connection = connection.connection
        self.cursor = self.connection.cursor()
        self.access_parking_lots = AccessParkingLots(conn=connection)
        self.access_users = AccessUsers(conn=connection)


    def map_feedback(self, feedback):
        feedback = dict(feedback)
        feedback["parking_lot"] = self.access_parking_lots.get_parking_lot(id=feedback["parking_lot_id"])
        feedback["user"] = self.access_users.get_user_byid(id=feedback["user_id"])
        feedback["created_at"] = datetime.strptime(feedback["created_at"], "%Y-%m-%d %H:%M:%S")
        del feedback["parking_lot_id"]
        del feedback ["user_id"]
        
        return Feedback(**feedback)


    def get_feedback_by_parkinglot_id(self, parkinglot_id: int) -> list[Feedback]:
        query = """
        SELECT * FROM feedback
        WHERE parking_lot_id = ?;
        """
        self.cursor.execute(query, [parkinglot_id])
        raw_feedback = self.cursor.fetchall()

        return list(self.map_feedback(feedback) for feedback in raw_feedback)
    

    def add_feedback(self, feedback: Feedback):
        query = """
        INSERT INTO feedback
            (user_id, parking_lot_id, rating, comment, created_at)
        VALUES
            (user_id, :parking_lot_id, :rating, :comment, :created_at)
        RETURNING id;
        """
        feedback_dict = feedback.dict()
        feedback_dict["parking_lot_id"] = feedback["parking_lot"].id
        feedback_dict["user_id"] = feedback["user"].id
        self.cursor.execute(query, feedback_dict)
        feedback.id = self.cursor.fetchone()[0]
        self.connection.commit()


    def delete_feedback(self, feedback: Feedback):
        query = """
        DELETE FROM feedback
        WHERE id = :id;
        """
        self.cursor.execute(query, feedback.dict())