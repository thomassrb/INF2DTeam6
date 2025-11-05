from typing import List, Dict, Any
from datetime import datetime
from storage_utils import load_payment_data
from hashlib import md5
import math
import uuid

def calculate_price(parkinglot, sid, data):
    # Deze functie berekent de prijs op basis van je start en end tijd.

    start_time = datetime.strptime(data["started"], "%d-%m-%Y %H:%M:%S")
    end_time = datetime.strptime(data["stopped"], "%d-%m-%Y %H:%M:%S") if data.get("stopped") else datetime.now()

    duration = end_time - start_time
    total_hours = math.ceil(duration.total_seconds() / 3600)
    total_days = math.ceil(duration.total_seconds() / 86400)

    hourly_rate = float(parkinglot.get("tariff", 0))
    daily_rate = float(parkinglot.get("daytariff", 999))

    if duration.total_seconds() < 180:  # Dus als je minder dan 3 min parked dan is het gratis 
        price = 0.0
    elif total_days > 0:    # als je meer dan een dag parkeerd 
        price = daily_rate * total_days
    else:                   # als je binnen een dag parkeerd
        price = min(hourly_rate * total_hours, daily_rate)
    
    return price, total_hours, total_days




def generate_payment_hash(sid, data):
    # Hier generated die en md5 hash voor de betaling
    lp = data.get("license_plate") or data.get("licenseplate") or ""
    return md5(str(sid + data["licenseplate"]).encode("utf-8")).hexdigest()


def generate_transaction_validation_hash():
    return str(uuid.uuid4())

def check_payment_amount(tx_hash):
    # Deze functie returned het bedrag van een transactie

    payments = load_payment_data()

    return sum(
        payment.get("amount", 0)                    # type: ignore
        for payment in payments                     # type: ignore
        if payment.get("transaction") == tx_hash    # type: ignore
    )