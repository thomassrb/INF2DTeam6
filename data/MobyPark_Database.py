# Voor de database, allereerst moet je doen:
# pip install mysql-connector-python

import sqlite3

DB_CONFIG = {
    'host': 'localhost',
    'user': 'MobyPark_admin',
    'password': 'MobyPark_admin_8*'
}

DATABASE_NAME = "MobyPark_db"


def create_database_and_tables():

    connection = sqlite3.connect("data/mobypark_database.db")
    cursor = connection.cursor()

    users_table_query = """
    CREATE TABLE IF NOT EXISTS users(
        id INT AUTO_INCREMENT PRIMARY KEY,
        username TINYTEXT NOT NULL UNIQUE,
        name TINYTEXT NOT NULL,
        email TINYTEXT NOT NULL UNIQUE,
        password TINYTEXT NOT NULL,
        created_at DATETIME NOT NULL,
        phone TINYTEXT NOT NULL,
        role TINYTEXT NOT NULL,
        birth_year INT NOT NULL,
        active BOOL NOT NULL
    );

    
    """

    cursor.execute(users_table_query)
    print("Table 'users' ensured to exist.")

    cursor.close()
    connection.close()


if __name__ == "__main__":
    create_database_and_tables()
