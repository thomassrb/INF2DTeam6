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


def migrate_users():
    users = load_json("users.json")
    falsive_data = []
    user_keys = {"id", "username", "name", "email", "password", "created_at", "phone", "birth_year", "role", "active"}
    datadump_query = """
INSERT INTO users
(id, username, name, email, password, created_at, phone, birth_year, role, active)
VALUES
(:id, :username, :name, :email, :password, :created_at, :phone, :birth_year, :role, :active)
"""

    for user in users:
        if set(user.keys()) != user_keys:
            falsive_data.append(user)
            logger(file="falsive_user_logs.txt", data=user, error="missing key")
        elif "" in user.values():
            falsive_data.append(user)
            logger(file="falsive_user_logs.txt", data=user, error="missing value")
        else:
            final_user = user.copy()
            final_user["created_at"] = datetime.strptime(final_user["created_at"], "%Y-%m-%d")
            try:
                connection.cursor.execute(datadump_query, final_user)
            except sqlite3.IntegrityError as e:
                falsive_data.append(user)
                logger(file="falsive_user_logs.txt", data=user, error=e)


    connection.connection.commit()
    connection.close_connection()
    write_json(filename="falsive_users.json", data=falsive_data)
    

def migrate_parking_lots():
    parking_lots = load_json("parking.json")
    falsive_data = dict()
    parking_lot_keys = {"id", "username", "name", "email", "password", "created_at", "phone", "birth_year", "role", "active"}
    datadump_query = """
INSERT INTO users
(id, username, name, email, password, created_at, phone, birth_year, role, active)
VALUES
(:id, :username, :name, :email, :password, :created_at, :phone, :birth_year, :role, :active)
"""

    for parking_lot in parking_lots:
        if set(parking_lot.keys()) != parking_lot_keys:
            falsive_data["missing_keys"].append(parking_lot)
        elif "" in parking_lot.values():
            falsive_data["missing_values"].append(parking_lot)
        else:
            parking_lot["created_at"] = datetime.strptime(parking_lot["created_at"], "%Y-%m-%d")
            try:
                connection.cursor.execute(datadump_query, parking_lot)
            except sqlite3.IntegrityError as e:
                falsive_data["duplicates"].append(parking_lot)


    connection.connection.commit()
    connection.close_connection()
    write_json(filename="falsive_users.json", data=falsive_data)


if "__main__" ==  __name__:

    migrate_users()
