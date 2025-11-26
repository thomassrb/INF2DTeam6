from datetime import datetime

class User:

    def __init__(self,
                 id: str,
                 username: str,
                 name: str,
                 email: str,
                 password: str,
                 created_at: datetime,
                 phone: str,
                 role: str,
                 birth_year: int,
                 active: bool):
        
        self.id = id
        self.username = username
        self.name = name
        self.email = email
        self.password = password
        self.created_at = created_at
        self.phone = phone
        self.role = role
        self.birth_year = birth_year
        self.active = active

    
    def __repr__(self):
        return self.username
    



# id VARCHAR(255) PRIMARY KEY,
# username VARCHAR(255) NOT NULL UNIQUE,
# name VARCHAR(255) NOT NULL,
# email VARCHAR(255) NOT NULL UNIQUE,
# password VARCHAR(255) NOT NULL,
# created_at DATETIME NOT NULL,
# phone VARCHAR(255) NOT NULL,
# role VARCHAR(255) NOT NULL,
# birth_year INT NOT NULL,
# active BOOL NOT NULL