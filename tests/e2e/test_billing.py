import time
import requests
import pytest

BASE = "http://localhost:8000"


def create_parking_lot(admin_token: str, name: str) -> str:
    payload = {
        "name": name,
        "location": "Center",
        "capacity": 50,
        "tariff": 3.0,
        "daytariff": 15.0,
        "address": "E2E Blvd 1",
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


def test_billing_for_user_after_session(server_process, admin_token, user_token):
    username, u_token = user_token
    lot_id = create_parking_lot(admin_token, name=f"E2E Billing Lot {int(time.time())}")

    plate = f"E2E-{int(time.time())}"
    r1 = requests.post(
        f"{BASE}/api/parking-lots/{lot_id}/sessions/start",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    if r1.status_code == 404:
        pytest.skip("sessions endpoints not implemented")
    assert r1.status_code == 200, r1.text

    r2 = requests.post(
        f"{BASE}/api/parking-lots/{lot_id}/sessions/stop",
        json={"licenseplate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r2.status_code == 200, r2.text

    # Admin queries gedeelte
    rb = requests.get(
        f"{BASE}/api/users/{username}/billing",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    if rb.status_code == 404:
        pytest.skip("billing endpoint not implemented")
    assert rb.status_code == 200, rb.text
    items = rb.json()
    assert isinstance(items, list)
    assert any(
        isinstance(it, dict) and "amount" in it and "session" in it for it in items
    ), f"Expected billing items for user {username}, got: {items}"
