from datetime import datetime

class TransactionData:

    def __init__(self,
                 id: str,
                 amount: float,
                 date: datetime,
                 method: str,
                 issuer: str,
                 bank: str):
        
        self.id = id
        self.amount = amount
        self.date = date
        self.method = method
        self.issuer = issuer
        self.bank = bank

    
    def __repr__(self):
        return self.__dict__
        