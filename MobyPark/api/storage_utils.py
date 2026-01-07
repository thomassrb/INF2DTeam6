# storage_utils.py
import os
import json
import csv
import threading
from typing import Dict, List, Any, Optional

# File operations lock
json_file_lock = threading.Lock()
csv_file_lock = threading.Lock()
text_file_lock = threading.Lock()

# Get the data directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.environ.get('MOBYPARK_DATA_DIR') or os.path.join(PROJECT_ROOT, 'MobyPark-api-data', 'pdata')
os.makedirs(DATA_DIR, exist_ok=True)

def load_json(filename: str) -> dict:
    """Load data from a JSON file."""
    full_path = os.path.join(DATA_DIR, filename)
    with json_file_lock:
        try:
            with open(full_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                return data
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            return {}

def save_json(filename: str, data: Any) -> None:
    """Save data to a JSON file."""
    full_path = os.path.join(DATA_DIR, filename)
    with json_file_lock:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=2)

def load_csv(filename: str) -> List[Dict[str, str]]:
    """Load data from a CSV file."""
    full_path = os.path.join(DATA_DIR, filename)
    with csv_file_lock:
        try:
            with open(full_path, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                return list(reader)
        except FileNotFoundError:
            return []

def save_csv(filename: str, data: List[Dict[str, str]]) -> None:
    """Save data to a CSV file."""
    full_path = os.path.join(DATA_DIR, filename)
    with csv_file_lock:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8', newline='') as file:
            if data:
                writer = csv.DictWriter(file, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)

def load_text(filename: str) -> str:
    """Load text from a file."""
    full_path = os.path.join(DATA_DIR, filename)
    with text_file_lock:
        try:
            with open(full_path, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            return ''

def save_text(filename: str, text: str) -> None:
    """Save text to a file."""
    full_path = os.path.join(DATA_DIR, filename)
    with text_file_lock:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8') as file:
            file.write(text)

# Legacy functions for backward compatibility
def load_data(filename: str) -> Any:
    """Legacy function to load data from a file."""
    if filename.endswith('.json'):
        return load_json(filename)
    elif filename.endswith('.csv'):
        return load_csv(filename)
    return load_text(filename)

def save_data(filename: str, data: Any) -> None:
    """Legacy function to save data to a file."""
    if filename.endswith('.json'):
        save_json(filename, data)
    elif filename.endswith('.csv'):
        save_csv(filename, data)
    else:
        save_text(filename, str(data))