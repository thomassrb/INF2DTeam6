from typing import List, Dict, Any
from datetime import datetime
from hashlib import md5
import math
import uuid

from MobyPark.api.storage_utils import load_payment_data
from MobyPark.api.Models.User import User
from MobyPark.api.Models.ParkingLot import ParkingLot


def calculate_price(parkinglot, session: User):
    # Deze functie berekent de prijs op basis van je start en end tijd.
    start_time = session.started
    end_time = session.stopped

    end_time = end_time or datetime.now()

    try:
        duration = end_time - start_time
    except Exception:
        # Ongeldige datum → gratis + geen uren/dagen
        return 0.0, 0, 0

    seconds = duration.total_seconds()
    total_hours = math.ceil(seconds / 3600)
    total_days = math.floor(seconds / 86400)

    hourly_rate = parkinglot.tariff
    daily_rate = parkinglot.daytariff

    if duration.total_seconds() < 180:  # Dus als je minder dan 3 min parked dan is het gratis 
        price = 0.0
    elif total_days > 0:    # als je meer dan een dag parkeerd 
        price = daily_rate * total_days
    else:                   # als je binnen een dag parkeerd
        price = min(hourly_rate * total_hours, daily_rate)
    
    return price, total_hours, total_days


def generate_payment_hash(sid, data):
    # Hier generated die en md5 hash voor de betaling
    lp = data.licenseplate
    return md5(str(sid + lp).encode("utf-8")).hexdigest()


def generate_transaction_validation_hash():
    return str(uuid.uuid4())


def check_payment_amount(tx_hash):
    # Deze functie returned het bedrag van een transactie

    payments = load_payment_data()

    return sum(
        payment.get("amount", 0)                    
        for payment in payments                     
        if payment.get("transaction") == tx_hash    
    )
