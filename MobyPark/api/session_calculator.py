import os
from datetime import datetime
from .storage_utils import load_payment_data
from hashlib import md5
import math
import uuid


_TXN_SECRET = os.environ.get('MOBYPARK_TXN_SECRET', 'super-secret-transaction-key')

def calculate_price(parkinglot: dict, session_id: str, session: dict) -> tuple[float, int, int]:
    start_time_str = session["started"]
    stop_time_str = session["stopped"]

    if not stop_time_str:
        return 0.0, 0, 0

    FMT = "%d-%m-%Y %H:%M:%S"

    start_time = datetime.strptime(start_time_str, FMT)
    stop_time = datetime.strptime(stop_time_str, FMT)

    duration = stop_time - start_time
    total_hours = duration.total_seconds() / 3600
    total_days = duration.days

    hourly_rate = parkinglot.get("hourly_rate", parkinglot.get("tariff", 0.0))
    day_rate = parkinglot.get("day_rate", parkinglot.get("daytariff", 0.0))

    amount = (total_days * day_rate) + ((total_hours % 24) * hourly_rate)

    return round(amount, 2), int(total_hours), total_days

def generate_payment_hash(session_id: str, session: dict) -> str:
    hash_str = f"{session_id}-{session['licenseplate']}-{session['started']}-{_TXN_SECRET}"
    return hashlib.sha256(hash_str.encode()).hexdigest()

def generate_transaction_validation_hash() -> str:
    return hashlib.sha256(os.urandom(64)).hexdigest()

def check_payment_amount(transaction_hash: str) -> float:
    payments = load_payment_data()
    total_paid = 0.0
    for payment in payments:
        if payment.get("hash") == transaction_hash and payment.get("completed"):
            total_paid += float(payment.get("amount", 0.0))
    return total_paid