from datetime import datetime

class Payment:

    def __init__(self,
                 transaction: str,
                 amount: float,
                 initiator: str,
                 user_id: str, # will change to user object later on
                 created_at: datetime,
                 completed: datetime,
                 hash: str,
                 session_id: str, # will change to session object later on
                 parking_lot_id: str): # will change to parking_lot object later on
            # might add t_data object to make it more compact
        
        self.transaction = transaction
        self.amount = amount
        self.initiator = initiator
        self.user_id = user_id
        self.created_at = created_at
        self.completed = completed
        self.hash = hash
        self.session_id = session_id
        self.parking_lot_id = parking_lot_id
