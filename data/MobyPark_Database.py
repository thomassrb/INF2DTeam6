# Voor de database, allereerst moet je doen:
# pip install mysql-connector-python

import mysql.connector

DB_CONFIG = {
    'host': 'localhost',
    'user': 'MobyPark_admin',
    'password': 'MobyPark_admin_8*'
}

DATABASE_NAME = "MobyPark_db"


def create_database_and_tables():
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor()

        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE_NAME}")
        print(f"Database '{DATABASE_NAME}' ensured to exist.")

        cnx.database = DATABASE_NAME

        # Dit nog aan te passen naar de benodigde dingen ig
        users_table_query = """
        CREATE TABLE IF NOT EXIST users(
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """

        cursor.execute(users_table_query)
        print("Table 'users' ensured to exist.")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        if 'cnx' in locals() and cnx.is_connected():
            cursor.close()
            cnx.close()
            print("MySQL connection closed.")


if __name__ == "__main__":
    create_database_and_tables()
