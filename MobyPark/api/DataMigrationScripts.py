from DBConnection import DBConnection
import os
from datetime import datetime
import sqlite3
from storage_utils import load_json, write_json

connection = DBConnection("MobyPark/api/data/MobyParkData.db")

def logger(file, data, error):
    file_directory = os.path.dirname(os.path.abspath(__file__))
    data_directory = os.path.join(file_directory, 'data')
    file_path = os.path.join(data_directory, file)

    try:
        with open(file=file_path, mode='a') as file:
            file.write(f"{str(data)} ERROR: {error}\n")
    except FileNotFoundError:
        print("ERROR: file not found")
        quit()


def migrate_data(falsive_data, log_file, query, data, final_data):
    try:
        connection.cursor.execute(query, final_data)
    except sqlite3.IntegrityError as e:
        falsive_data.append(data)
        logger(file=log_file, data=data, error=e)
    except sqlite3.OperationalError as e:
        falsive_data.append(data)
        logger(file=log_file, data=data, error=e)


def migrate_users():
    users = load_json("users.json")
    falsive_data = list()
    datadump_query = """
INSERT INTO users
(id, username, name, email, password, created_at, phone, birth_year, role, active)
VALUES
(:id, :username, :name, :email, :password, :created_at, :phone, :birth_year, :role, :active)
"""

    for user in users:
        final_user = user.copy()
        final_user["created_at"] = datetime.strptime(final_user["created_at"], "%Y-%m-%d")
        migrate_data(falsive_data=falsive_data, log_file="falsive_user_logs.txt", data=user, final_data=final_user, query=datadump_query)

    connection.connection.commit()
    connection.close_connection()
    write_json(filename="falsive_users.json", data=falsive_data)
    

def migrate_parking_lots():
    parking_lots = load_json("parking-lots.json")
    falsive_data = list()
    datadump_query = """
INSERT INTO parking_lots
(id, name, location, address, capacity, created_at, reserved, tariff, daytariff)
VALUES
(:id, :name, :location, :address, :capacity, :created_at, :reserved, :tariff, :daytariff)
"""
    coordinatesdump_query = """
INSERT INTO parking_lots_coordinates
(id, lng, lat)
VALUES
(:id, :lng, :lat)
"""

    for parking_lot in parking_lots.values():
        final_parking_lot = parking_lot.copy()
        final_parking_lot["created_at"] = datetime.strptime(final_parking_lot["created_at"], "%Y-%m-%d")
        migrate_data(log_file="falsive_parking_lot_logs.txt", falsive_data=falsive_data, query=datadump_query, data=parking_lot, final_data=final_parking_lot)

        coordinates = parking_lot["coordinates"].copy()
        coordinates["id"] = parking_lot["id"]
        migrate_data(log_file="falsive_parking_lot_logs.txt", falsive_data=falsive_data, query=coordinatesdump_query, data=parking_lot, final_data=coordinates)

    connection.connection.commit()
    connection.close_connection()
    write_json(filename="falsive_parking_lots.json", data=falsive_data)


if "__main__" ==  __name__:

    migrate_parking_lots()
