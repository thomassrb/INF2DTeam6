import time
import requests
import pytest
import re

BASE = "http://localhost:8000"


def create_parking_lot(admin_token: str, name: str) -> str:
    unique_addr = f"E2E Blvd 1 {int(time.time())}"
    payload = {
        "name": name,
        "location": "Center",
        "capacity": 50,
        "tariff": 3.0,
        "daytariff": 15.0,
        "address": unique_addr,
        "coordinates": {"lat": 52.0, "lng": 4.0},
    }
    r = requests.post(
        f"{BASE}/api/parkinglots",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    if r.status_code == 404:
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert r.status_code in (200, 201), r.text
    # API usually returns a message like: "Parking lot saved under ID: {id}"
    try:
        body = r.json()
    except Exception:
        body = {}

    msg = str(body.get("Server message", ""))
    m = re.search(r"\bID:\s*(\d+)\b", msg)
    if m:
        return m.group(1)

    # Fallback: fetch list and match by unique address
    rlist = requests.get(f"{BASE}/api/parkinglots", timeout=5)
    assert rlist.status_code == 200, rlist.text
    lots = rlist.json()
    lot = next((l for l in lots if l.get("address") == unique_addr), None)
    assert lot is not None, f"Created parking lot not found in list for address={unique_addr}"
    lot_id = lot.get("id")
    assert lot_id is not None, "Parking lot list did not include id"
    return str(lot_id)


def test_billing_for_user_after_session(server_process, admin_token, user_token):
    username, u_token = user_token
    lot_id = create_parking_lot(admin_token, name=f"E2E Billing Lot {int(time.time())}")

    plate = f"E2E-{int(time.time())}"
    r1 = requests.post(
        f"{BASE}/api/parkinglots/{lot_id}/sessions/start",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    if r1.status_code == 404:
        pytest.skip("sessions endpoints not implemented")
    assert r1.status_code == 200, r1.text

    r2 = requests.post(
        f"{BASE}/api/parkinglots/{lot_id}/sessions/stop",
        json={"licenseplate": plate},
        headers={"Authorization": f"Bearer {u_token}"},
        timeout=5,
    )
    assert r2.status_code == 200, r2.text

    # Admin queries gedeelte
    rb = requests.get(
        f"{BASE}/api/billing/{username}",
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
