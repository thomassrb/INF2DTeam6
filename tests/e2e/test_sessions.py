import requests
import time
import pytest

BASE = "http://localhost:8000"


def create_parking_lot(admin_token: str, name: str = "E2E Lot") -> str:
    payload = {
        "name": name,
        "location": "Rotterdam",
        "capacity": 100,
        "tariff": 2.5,
        "daytariff": 12.0,
        "address": "Wijnhaven 100",
        "coordinates": {"latitude": 52.0, "longitude": 4.0},
    }
    r = requests.post(
        f"{BASE}/api/parking-lots",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    if r.status_code == 404:
        pytest.skip("/api/parking-lots endpoint not implemented")
    assert r.status_code in (200, 201), r.text
    lot = r.json()
    lot_id = lot.get("id") or lot.get("parking_lot", {}).get("id")
    assert lot_id, "Failed to resolve created parking lot id"
    return lot_id


def test_session_start_stop_flow(server_process, admin_token, user_token):
    username, u_token = user_token
    lot_id = create_parking_lot(admin_token, name=f"E2E Lot {int(time.time())}")

    # Hier start die zeg maar een session
    r1 = requests.post(
        f"{BASE}/api/parking-lots/{lot_id}/sessions/start",
        json={"license_plate": "E2E-PLATE-1"},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    if r1.status_code == 404:
        pytest.skip("sessions endpoints not implemented")
    assert r1.status_code == 200, r1.text

    # Hier start die er opnieuw een wat zou moeten resulteren in een 409
    r2 = requests.post(
        f"{BASE}/api/parking-lots/{lot_id}/sessions/start",
        json={"license_plate": "E2E-PLATE-1"},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r2.status_code == 409, r2.text

    # Session stoppen met legacy key
    r3 = requests.post(
        f"{BASE}/api/parking-lots/{lot_id}/sessions/stop",
        json={"licenseplate": "E2E-PLATE-1"},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r3.status_code == 200, r3.text
