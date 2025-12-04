import time
import requests

BASE = "http://localhost:8000"


def create_parking_lot(admin_token: str, name: str) -> str:
    payload = {
        "name": name,
        "location": "Center",
        "capacity": 50,
        "tariff": 3.0,
        "daytariff": 15.0,
        "address": "E2E Blvd 1",
        "coordinates": [52.0, 4.0],
    }
    r = requests.post(
        f"{BASE}/parking-lots",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    assert r.status_code in (200, 201), r.text
    lots = requests.get(f"{BASE}/parking-lots", timeout=5).json()
    lot_id = next((lid for lid, lot in lots.items() if lot.get("name") == name), None)
    assert lot_id, "Failed to resolve created parking lot id"
    return lot_id


def test_billing_for_user_after_session(server_process, admin_token, user_token):
    username, u_token = user_token
    lot_id = create_parking_lot(admin_token, name=f"E2E Billing Lot {int(time.time())}")

    plate = f"E2E-{int(time.time())}"
    r1 = requests.post(
        f"{BASE}/parking-lots/{lot_id}/sessions/start",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r1.status_code == 200, r1.text

    r2 = requests.post(
        f"{BASE}/parking-lots/{lot_id}/sessions/stop",
        json={"licenseplate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r2.status_code == 200, r2.text

    # Admin queries gedeelte
    rb = requests.get(
        f"{BASE}/billing/{username}",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    assert rb.status_code == 200, rb.text
    items = rb.json()
    assert isinstance(items, list)
    assert any(
        isinstance(it, dict) and "amount" in it and "session" in it for it in items
    ), f"Expected billing items for user {username}, got: {items}"
