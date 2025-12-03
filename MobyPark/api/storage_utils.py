import json
import csv
import os
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
# Dit zorgt ervoor dat testes data files mogen overriden
DATA_DIR = os.environ.get('MOBYPARK_DATA_DIR') or os.path.join(PROJECT_ROOT, 'MobyPark\\api\\data')

# Zeker weten dat de data directory uberhaupt bestaat
os.makedirs(DATA_DIR, exist_ok=True)

# Een beveiliging die ervoor zorgt dat meerdere threads niet tegelijk hetzelfde JSON-bestand kunnen aanpassen
# dit vermijdt de mogelijkheid op data verlies in de jsons
json_file_lock = threading.Lock()

def load_json(filename):
    full_path = os.path.join(DATA_DIR, filename)
    print(f"DEBUG: load_json trying to open: {full_path}")
    with json_file_lock:
        try:
            with open(full_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                print(f"DEBUG: Successfully loaded JSON from {filename}. Data type: {type(data)}")
                return data
        except FileNotFoundError:
            print(f"DEBUG: FileNotFoundError for {filename}. Returning empty dictionary.")
            return {}
        except json.JSONDecodeError:
            print(f"DEBUG: Error decoding JSON from {filename}. Returning empty dictionary.")
            return {}

def write_json(filename, data):
    full_path = os.path.join(DATA_DIR, filename)
    with json_file_lock:
        try:
            with open(full_path, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4)
        except IOError as e:
            print(f"Error writing JSON to {filename}: {e}")

def load_csv(filename):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            return [row for row in reader]
    except FileNotFoundError:
        return []
    except csv.Error as e:
        print(f"Error loading CSV from {filename}: {e}")
        return []

def write_csv(filename, data):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            for row in data:
                writer.writerow(row)
    except IOError as e:
        print(f"Error writing CSV to {filename}: {e}")

def load_text(filename):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'r', encoding='utf-8') as file:
            return file.readlines()
    except FileNotFoundError:
        return []
    except IOError as e:
        print(f"Error loading text from {filename}: {e}")
        return []

def write_text(filename, data):
    full_path = os.path.join(DATA_DIR, filename)
    try:
        with open(full_path, 'w', encoding='utf-8') as file:
            for line in data:
                file.write(line + '\n')
    except IOError as e:
        print(f"Error writing text to {filename}: {e}")

def save_data(filename, data):
    if filename.endswith('.json'):
        write_json(filename, data)
    elif filename.endswith('.csv'):
        write_csv(filename, data)
    elif filename.endswith('.txt'):
        write_text(filename, data)
    else:
        raise ValueError("Unsupported file format")

def load_data(filename):
    if filename.endswith('.json'):
        return load_json(filename)
    elif filename.endswith('.csv'):
        return load_csv(filename)
    elif filename.endswith('.txt'):
        return load_text(filename)
    else:
        return None

def load_user_data():
    return load_data('users.json')

def save_user_data(data):
    save_data('users.json', data)

def load_parking_lot_data():
    return load_data('parking-lots.json')

def save_parking_lot_data(data):
    save_data('parking-lots.json', data)

def load_reservation_data():
    return load_data('reservations.json')

def save_reservation_data(data):
    save_data('reservations.json', data)

def load_payment_data():
    return load_data('payments.json')

def save_payment_data(data):
    save_data('payments.json', data)

def load_discounts_data():
    return load_data('discounts.csv')

def save_discounts_data(data):
    save_data('discounts.csv', data)

def load_vehicles_data():
    data = load_data('vehicles.json')
    # Ensure we always work with a dict keyed by username -> list[vehicle]
    if isinstance(data, dict):
        return data
    # Handle legacy flat-list formats defensively
    if isinstance(data, list):
        return {"__legacy__": data}
    # Fallback to empty mapping
    return {}


def save_vehicles_data(data):
    save_data('vehicles.json', data)