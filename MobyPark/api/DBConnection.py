import sqlite3

class DBConnection:

    def __init__(self, database_path):
        self.connection = sqlite3.connect(database_path)
        self.cursor = self.connection.cursor()
        self.create_database_and_tables()


    def create_database_and_tables(self):
        users_table_query = """
        CREATE TABLE IF NOT EXISTS users(
            id VARCHAR(255) PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            phone VARCHAR(255) NOT NULL,
            role VARCHAR(255) NOT NULL,
            birth_year INT NOT NULL,
            active BOOL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS parking_lots(
            id VARCHAR(255) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            location VARCHAR(255) NOT NULL UNIQUE,
            address VARCHAR(255) NOT NULL UNIQUE,
            capacity INT NOT NULL,
            reserved INT NOT NULL,
            tariff DECIMAL(10,2) NOT NULL,
            daytariff DECIMAL(10,2) NOT NULL,
            created_at DATETIME NOT NULL
        );

        CREATE TABLE IF NOT EXISTS parking_lots_coordinates(
            id VARCHAR(255) PRIMARY KEY,
            lng FLOAT NOT NULL,
            lat FLOAT NOT NULL,
            FOREIGN KEY (id) REFERENCES parking_lots(id)
        );

        CREATE TABLE IF NOT EXISTS vehicles(
            id VARCHAR(255) PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            license_plate VARCHAR(255) NOT NULL UNIQUE,
            make VARCHAR(255) NOT NULL,
            model VARCHAR(255) NOT NULL,
            color VARCHAR(255) NOT NULL,
            year INT NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sessions(
            id VARCHAR(255) PRIMARY KEY,
            parking_lot_id VARCHAR(255) NOT NULL,
            vehicle_id VARCHAR(255) NOT NULL,
            started DATETIME NOT NULL,
            stopped DATETIME NOT NULL,
            user_id VARCHAR(255) NOT NULL,
            duration_minutes INT NOT NULL,
            cost DECIMAL(10,2) NOT NULL,
            payment_status VARCHAR(255) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (parking_lot_id) REFERENCES parking_lots(id),
            FOREIGN KEY (vehicle_id) REFERENCES vehicles(id)
        );

        CREATE TABLE IF NOT EXISTS payments(
            id VARCHAR(255) PRIMARY KEY,
            amount DECIMAL(10,2) NOT NULL,
            initiator VARCHAR(255) NOT NULL,
            user_id VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            completed DATETIME NOT NULL,
            hash VARCHAR(255) NOT NULL,
            session_id VARCHAR(255) NOT NULL,
            parking_lot_id VARCHAR(255) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (parking_lot_id) REFERENCES parking_lots(id),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS t_data(
            id VARCHAR(255) PRIMARY KEY,
            amount DECIMAL(10,2) NOT NULL,
            date DATETIME NOT NULL,
            method VARCHAR(255) NOT NULL,
            issuer VARCHAR(255) NOT NULL,
            bank VARCHAR(255) NOT NULL,
            FOREIGN KEY (id) REFERENCES payments(id)
        );

        CREATE TABLE IF NOT EXISTS reservations(
            id VARCHAR(255) PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            parking_lot_id VARCHAR(255) NOT NULL,
            vehicle_id VARCHAR(255) NOT NULL,
            start_time DATETIME NOT NULL,
            end_time DATETIME NOT NULL,
            status VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            cost DECIMAL(10,2) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (parking_lot_id) REFERENCES parking_lots(id),
            FOREIGN KEY (vehicle_id) REFERENCES vehicles(id)
        );

        CREATE TABLE IF NOT EXISTS discounts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discount INT NOT NULL
        );
        """

        self.cursor.executescript(users_table_query)
    

    def close_connection(self):
        self.cursor.close()
        self.connection.close()


