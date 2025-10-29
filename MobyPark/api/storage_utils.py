import json
import csv
import os
from tinydb import TinyDB, Query
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, '..', '..', 'data')
os.makedirs(DATA_DIR, exist_ok=True)

_db_cache = {}
_db_lock = threading.Lock()

def db_init(filename):
    with _db_lock:
        if filename not in _db_cache:
            full_path = os.path.join(DATA_DIR, filename)
            _db_cache[filename] = TinyDB(full_path)
        return _db_cache[filename]

def load_json(filename):
    db = db_init(filename)
    return db.all()

def write_json(filename, data):
    db = db_init(filename)
    db.truncate()
    db.insert_multiple(data)

def load_csv(filename):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'r') as file:
            reader = csv.reader(file)
            return [row for row in reader]
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error loading CSV from {filename}: {e}")
        return []

def write_csv(filename, data):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'w', newline='') as file:
            writer = csv.writer(file)
            for row in data:
                writer.writerow(row)
    except IOError as e:
        print(f"Error writing CSV to {filename}: {e}")

def load_text(filename):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error loading text from {filename}: {e}")
        return []

def write_text(filename, data):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'w') as file:
            for line in data:
                file.write(line + '\n')
    except IOError as e:
        print(f"Error writing text to {filename}: {e}")

def save_data(filename, data):
    if filename.endswith('.json'):
        db = db_init(filename)
        db.truncate()
        db.insert_multiple(data)
    elif filename.endswith('.csv'):
        write_csv(filename, data)
    elif filename.endswith('.txt'):
        write_text(filename, data)
    else:
        raise ValueError("Unsupported file format") 

def load_data(filename):
    if filename.endswith('.json'):
        db = db_init(filename)
        return db.all()
    elif filename.endswith('.csv'):
        return load_csv(filename)
    elif filename.endswith('.txt'):
        return load_text(filename)
    else:
        return None

def load_user_data():
    db = db_init('users.json')
    return [dict(item) for item in db.all()]

def save_user_data(data):
    db = db_init('users.json')
    db.truncate()
    if data:
        db.insert_multiple(data)

def load_parking_lot_data():
    db = db_init('parking-lots.json')
    return {str(item['id']): item for item in db.all()} if db.all() else {}

def save_parking_lot_data(data):
    db = db_init('parking-lots.json')
    db.truncate()
    db.insert_multiple(list(data.values()))

def load_reservation_data():
    db = db_init('reservations.json')
    return {str(item['id']): item for item in db.all()} if db.all() else {}

def save_reservation_data(data):
    db = db_init('reservations.json')
    db.truncate()
    db.insert_multiple(list(data.values()))

def load_payment_data():
    db = db_init('payments.json')
    return [dict(item) for item in db.all()]

def save_payment_data(data):
    db = db_init('payments.json')
    db.truncate()
    if data:
        db.insert_multiple(data)

def load_discounts_data():
    return load_data('discounts.csv')

def save_discounts_data(data):
    save_data('discounts.csv', data)

def load_vehicles_data():
    db = db_init('vehicles.json')
    return db.all()

def save_vehicles_data(data):
    db = db_init('vehicles.json')
    db.truncate()
    db.insert_multiple(data)

def load_parking_lot_sessions(lid: str):
    db = db_init(f'pdata/p{lid}-sessions.json')
    return db.all()

def save_parking_lot_sessions(lid: str, data):
    db = db_init(f'pdata/p{lid}-sessions.json')
    db.truncate()
    db.insert_multiple(data)
