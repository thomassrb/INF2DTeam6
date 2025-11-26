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


def migrate_data(corrupt_data, log_file, query, data, final_data):
    try:
        connection.cursor.execute(query, final_data)
    except sqlite3.IntegrityError as e:
        corrupt_data.append(data)
        logger(file=log_file, data=data, error=e)
    except sqlite3.OperationalError as e:
        corrupt_data.append(data)
        logger(file=log_file, data=data, error=e)


def migrate_users():
    users = load_json("users.json")
    corrupt_data = list()
    datadump_query = """
INSERT INTO users
(id, username, name, email, password, created_at, phone, birth_year, role, active)
VALUES
(:id, :username, :name, :email, :password, :created_at, :phone, :birth_year, :role, :active)
"""

    for user in users:
        final_user = user.copy()
        final_user["created_at"] = datetime.strptime(final_user["created_at"], "%Y-%m-%d")
        final_user["id"] = int(final_user["id"])
        migrate_data(corrupt_data=corrupt_data, log_file="corrupt_user_logs.txt", data=user, final_data=final_user, query=datadump_query)

    connection.connection.commit()
    write_json(filename="corrupt_users.json", data=corrupt_data)
    

def migrate_parking_lots():
    parking_lots = load_json("parking-lots.json")
    corrupt_data = list()
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
        final_parking_lot["id"] = int(final_parking_lot["id"])
        migrate_data(log_file="corrupt_parking_lot_logs.txt", corrupt_data=corrupt_data, query=datadump_query, data=parking_lot, final_data=final_parking_lot)

        coordinates = parking_lot["coordinates"].copy()
        coordinates["id"] = final_parking_lot["id"]
        migrate_data(log_file="corrupt_parking_lot_logs.txt", corrupt_data=corrupt_data, query=coordinatesdump_query, data=parking_lot, final_data=coordinates)

    connection.connection.commit()
    if len(corrupt_data) > 0:
        write_json(filename="corrupt_parking_lots.json", data=corrupt_data)


def migrate_vehicles():
    vehicles = load_json("vehicles.json")
    corrupt_data = list()
    query = """
INSERT INTO vehicles
(id, user_id, licenseplate, make, model, color, year, created_at)
VALUES
(:id, :user_id, :license_plate, :make, :model, :color, :year, :created_at)
"""

    for vehicle in vehicles:
        final_vehicle = vehicle.copy()
        final_vehicle["created_at"] = datetime.strptime(final_vehicle["created_at"], "%Y-%m-%d")
        final_vehicle["id"] = int(final_vehicle["id"])
        final_vehicle["user_id"] = int(final_vehicle["user_id"])
        migrate_data(corrupt_data=corrupt_data, log_file="corrupt_vehicle_logs.txt", query=query, data=vehicle, final_data=final_vehicle)
    
    connection.connection.commit()
    if len(corrupt_data) > 0:
        write_json(filename="corrupt_vehicles.json", data=corrupt_data)


def migrate_sessions():
    for i in range(1500):
        print(i+1)
        sessions = load_json(f"pdata/p{i+1}-sessions.json")
        corrupt_data = list()
        query = """
INSERT INTO sessions
    (session_id, parking_lot_id, licenseplate, vehicle_id, started, stopped, username, user_id, duration_minutes, cost, payment_status)
SELECT
    :session_id,
    :parking_lot_id,
    :licenseplate,
    v.id,          
    :started,
    :stopped,
    :user,
    u.id,
    :duration_minutes,
    :cost,
    :payment_status
FROM (SELECT 1) AS dummy
LEFT JOIN vehicles v ON v.licenseplate = :licenseplate
LEFT JOIN users u ON u.username = :user;
"""
        

        for session in sessions.values():
            final_session = session.copy()
            final_session["started"] = datetime.strptime(final_session["started"], "%Y-%m-%dT%H:%M:%SZ")
            final_session["stopped"] = datetime.strptime(final_session["stopped"], "%Y-%m-%dT%H:%M:%SZ")
            final_session["session_id"] = int(final_session["id"])
            del final_session["id"]
            final_session["parking_lot_id"] = int(final_session["parking_lot_id"])
            migrate_data(corrupt_data=corrupt_data, log_file="corrupt_session_logs.txt", query=query, data=session, final_data=final_session)

        connection.connection.commit()
        if len(corrupt_data) > 0:
            write_json(filename="corrupt_vehicles.json", data=corrupt_data)


def migrate_payments():
    payments = load_json("payments.json")
    corrupt_data = list()
    length_payments = len(payments)
    t_data_query = """
INSERT INTO t_data
    (id, amount, date, method, issuer, bank)
VALUES
    (:id, :amount, :date, :method, :issuer, :bank)
"""

    query = """
INSERT INTO payments
    (id, amount, initiator, user_id, created_at, completed, hash, session_id, parking_lot_id)
SELECT
    :transaction,
    :amount,
    :initiator,
    u.id,
    :created_at,
    :completed,
    :hash,
    s.id,
    p.id
FROM sessions s
JOIN users u ON u.username = :initiator
JOIN parking_lots p ON p.id = :parking_lot_id
WHERE s.session_id = :session_id AND s.parking_lot_id = :parking_lot_id;
"""
    connection.cursor.executescript("""
    CREATE INDEX IF NOT EXISTS idx_sessions_session_parking
        ON sessions(session_id, parking_lot_id);
    """)

    counter = 0
    for payment in payments:
        counter += 1
        if counter % 100 == 0:
            print(f"{counter}/{length_payments} done")

        final_payment = payment.copy()
        try:
            created_at_timestamp = final_payment["created_at"].rsplit(":", 1)[0]
            completed_timestamp = final_payment["completed"].rsplit(":", 1)[0]
            final_payment["created_at"] = datetime.strptime(created_at_timestamp, "%d-%m-%Y %H:%M")
            final_payment["completed"] = datetime.strptime(completed_timestamp, "%d-%m-%Y %H:%M")
            final_payment["session_id"] = int(final_payment["session_id"])
        except KeyError as e:
            corrupt_data.append(payment)
            logger(file="corrupt_payment_logs.txt", data=payment, error=e)
        else:
            migrate_data(corrupt_data=corrupt_data, log_file="corrupt_payment_logs.txt", query=query, data=payment, final_data=final_payment)

            t_data = payment["t_data"]
            t_data["id"] = payment["transaction"]
            migrate_data(corrupt_data=corrupt_data, log_file="corrupt_payment_logs.txt", query=t_data_query, data=payment, final_data=t_data)

    connection.connection.commit()
    write_json(filename="corrupt_vehicles.json", data=corrupt_data) if len(corrupt_data) > 0 else None
        

def migrate_reservations():
    reservations = load_json("reservations.json")
    corrupt_data = list()
    query = """
INSERT INTO reservations
    (id, user_id, parking_lot_id, vehicle_id, start_time, end_time, status, created_at, cost)
VALUES
    (:id, :user_id, :parking_lot_id, :vehicle_id, :start_time, :end_time, :status, :created_at, :cost)
"""

    for reservation in reservations:
        final_reservation = reservation.copy()
        final_reservation["start_time"] =  datetime.strptime(final_reservation["start_time"], "%Y-%m-%dT%H:%M:%SZ")
        final_reservation["end_time"] =  datetime.strptime(final_reservation["end_time"], "%Y-%m-%dT%H:%M:%SZ")
        final_reservation["created_at"] =  datetime.strptime(final_reservation["created_at"], "%Y-%m-%dT%H:%M:%SZ")
        final_reservation["user_id"] = int(final_reservation["user_id"])
        final_reservation["parking_lot_id"] = int(final_reservation["parking_lot_id"])
        final_reservation["vehicle_id"] = int(final_reservation["vehicle_id"])
        migrate_data(corrupt_data=corrupt_data, log_file="corrupt_reservation_logs.txt", query=query, data=reservation, final_data=final_reservation)

    connection.connection.commit()
    write_json(filename="corrupt_vehicles.json", data=corrupt_data) if len(corrupt_data) > 0 else None


if "__main__" ==  __name__:
    # migrate_users()
    # migrate_parking_lots()
    # migrate_vehicles()
    # migrate_sessions()
    migrate_payments()
    migrate_reservations()
    connection.close_connection()
