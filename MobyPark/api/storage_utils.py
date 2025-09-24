import json
import csv

def load_json(filename):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        print(f"Error decoding JSON from {filename}. Returning empty list.")
        return []

def write_json(filename, data):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, default=str)
    except IOError as e:
        print(f"Error writing JSON to {filename}: {e}")

def load_csv(filename):
    try:
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            return [row for row in reader]
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error loading CSV from {filename}: {e}")
        return []

def write_csv(filename, data):
    try:
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            for row in data:
                writer.writerow(row)
    except IOError as e:
        print(f"Error writing CSV to {filename}: {e}")

def load_text(filename):
    try:
        with open(filename, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error loading text from {filename}: {e}")
        return []

def write_text(filename, data):
    try:
        with open(filename, 'w') as file:
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
    return load_data('data/users.json')

def save_user_data(data):
    save_data('data/users.json', data)

def load_parking_lot_data():
    return load_data('data/parking-lots.json')

def save_parking_lot_data(data):
    save_data('data/parking-lots.json', data)

def load_reservation_data():
    return load_data('data/reservations.json')

def save_reservation_data(data):
    save_data('data/reservations.json', data)

def load_payment_data():
    return load_data('data/payments.json')

def save_payment_data(data):
    save_data('data/payments.json', data)

def load_discounts_data():
    return load_data('data/discounts.csv')

def save_discounts_data(data):
    save_data('data/discounts.csv', data)
