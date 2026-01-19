import requests
import time
import pytest
import re

BASE = "http://localhost:8000"


def create_parking_lot(admin_token: str, name: str = "E2E Lot") -> str:
    unique_addr = f"Wijnhaven 100 {int(time.time())}"
    payload = {
        "name": name,
        "location": "Rotterdam",
        "capacity": 100,
        "tariff": 2.5,
        "daytariff": 12.0,
        "address": unique_addr,
        "coordinates": {"lat": 52.0, "lng": 4.0},
    }
    r = requests.post(
<<<<<<< HEAD
        f"{BASE}/parking-lots", 
        json=payload, 
        headers={"Authorization": f"Bearer {admin_token}"}, 
        timeout=5
    )
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]
=======
        f"{BASE}/api/parkinglots",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    if r.status_code == 404:
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert r.status_code in (200, 201), r.text
    try:
        body = r.json()
    except Exception:
        body = {}

    msg = str(body.get("Server message", ""))
    m = re.search(r"\bID:\s*(\d+)\b", msg)
    if m:
        return m.group(1)

    rlist = requests.get(f"{BASE}/api/parkinglots", timeout=5)
    assert rlist.status_code == 200, rlist.text
    lots = rlist.json()
    lot = next((l for l in lots if l.get("address") == unique_addr), None)
    assert lot is not None, f"Created parking lot not found in list for address={unique_addr}"
    lot_id = lot.get("id")
    assert lot_id is not None, "Parking lot list did not include id"
    return str(lot_id)
>>>>>>> nieuw_intergration_test


def test_session_start_stop_flow(server_process, admin_token, user_token):
    username, u_token = user_token
    lot_id = create_parking_lot(admin_token, name=f"E2E Lot {int(time.time())}")

    plate = f"E2E-PLATE-{int(time.time())}"

    # Hier start die zeg maar een session
    r1 = requests.post(
        f"{BASE}/api/parkinglots/{lot_id}/sessions/start",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    if r1.status_code == 404:
        pytest.skip("sessions endpoints not implemented")
    assert r1.status_code == 200, r1.text

    # Hier start die er opnieuw een wat zou moeten resulteren in een 409
    r2 = requests.post(
        f"{BASE}/api/parkinglots/{lot_id}/sessions/start",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r2.status_code == 409, r2.text

    # Session stoppen met legacy key
    r3 = requests.post(
        f"{BASE}/api/parkinglots/{lot_id}/sessions/stop",
        json={"licenseplate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r3.status_code == 200, r3.text
