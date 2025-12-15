import sqlite3

class DBConnection:

    def __init__(self, database_path):
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        
        self.cursor.execute("PRAGMA foreign_keys = ON")
        self.connection.commit()
        
        self.create_database_and_tables()


    def create_database_and_tables(self):
        users_table_query = """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            phone VARCHAR(255) NOT NULL,
            role VARCHAR(255) NOT NULL,
            birth_year INTEGER NOT NULL,
            active BOOL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS parking_lots (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            location TEXT,
            address TEXT,
            capacity INTEGER NOT NULL,
            reserved INTEGER DEFAULT 0,
            tariff REAL NOT NULL,
            daytariff REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS parking_lots_coordinates (
            id TEXT PRIMARY KEY,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            FOREIGN KEY (id) REFERENCES parking_lots (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vehicles(
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            licenseplate VARCHAR(255) NOT NULL UNIQUE,
            make VARCHAR(255) NOT NULL,
            model VARCHAR(255) NOT NULL,
            color VARCHAR(255) NOT NULL,
            year INTEGER NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sessions(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            parking_lot_id INTEGER NOT NULL,
            licenseplate VARCHAR(255) NOT NULL,
            vehicle_id INTEGER,
            started DATETIME NOT NULL,
            stopped DATETIME NOT NULL,
            username VARCHAR(255) NOT NULL,
            user_id INTEGER,
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
            user_id INTEGER NOT NULL,
            created_at DATETIME NOT NULL,
            completed DATETIME NOT NULL,
            hash VARCHAR(255) NOT NULL,
            session_id INTEGER NOT NULL,
            parking_lot_id INTEGER NOT NULL,
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
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            parking_lot_id INTEGER NOT NULL,
            vehicle_id INTEGER NOT NULL,
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
            id INTEGER PRIMARY KEY,
            discount INT NOT NULL
        );
        """

        self.cursor.executescript(users_table_query)
    

    def close_connection(self):
        self.cursor.close()
        self.connection.close()


