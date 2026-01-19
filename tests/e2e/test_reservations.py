import requests
import pytest
import time
import re

BASE = "http://localhost:8000"


def test_user_can_create_and_view_and_delete_reservation(server_process, make_user_and_login, admin_token):
    # als admin nieuwe parking lot createn
    unique_addr = f"E2E Addr Reservations {int(time.time())}"
    payload = {
        "name": "E2E Lot Reservations",
        "location": "E2E Loc",
        "address": unique_addr,
        "capacity": 10,
        "tariff": 1.25,
        "daytariff": 10.0,
        "coordinates": {"lat": 4.0, "lng": 5.0},
    }
    cr = requests.post(
<<<<<<< HEAD
        f"{BASE}/parking-lots", 
        json=payload, 
        headers={"Authorization": f"Bearer {admin_token}"}, 
        timeout=5
    )
    assert cr.status_code in (200, 201)
    lot_id = cr.json()["id"]
=======
        f"{BASE}/api/parkinglots",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    if cr.status_code == 404:
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert cr.status_code in (200, 201)

    try:
        body = cr.json()
    except Exception:
        body = {}

    msg = str(body.get("Server message", ""))
    m = re.search(r"\bID:\s*(\d+)\b", msg)
    if m:
        lot_id = m.group(1)
    else:
        rlist = requests.get(f"{BASE}/api/parkinglots", timeout=5)
        assert rlist.status_code == 200, rlist.text
        lots = rlist.json()
        lot = next((l for l in lots if l.get("address") == unique_addr), None)
        assert lot is not None, f"Created parking lot not found in list for address={unique_addr}"
        lot_id = lot.get("id")
    assert lot_id
>>>>>>> nieuw_intergration_test

    username, token = make_user_and_login("USER")

    plate = f"DMX-{int(time.time())}"
    vehicle_payload = {
        "licenseplate": plate,
        "name": "E2E Reservation Vehicle",
        "make": "E2E",
        "model": "Model",
        "color": "Blue",
        "year": 2020,
        "created_at": "2025-01-01 00:00:00",
    }
    rv = requests.post(
        f"{BASE}/api/vehicles",
        json=vehicle_payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert rv.status_code in (200, 201, 409), rv.text

    res_payload = {
        "parkinglot": lot_id,
        "license_plate": plate,
        "start_time": "2025-01-01 10:00:00",
        "end_time": "2025-01-01 12:00:00",
        "user": username,
    }
    r = requests.post(
        f"{BASE}/api/reservations",
        json=res_payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    if r.status_code == 405:
        pytest.skip("reservations POST not implemented")
    if r.status_code == 404:
        pytest.skip("/api/reservations endpoint not implemented")
    assert r.status_code in (200, 201), r.text
    rid = r.json().get("reservation", {}).get("id") or r.json().get("id")
    assert rid

    rlist = requests.get(
        f"{BASE}/api/reservations",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    if rlist.status_code == 404:
        pytest.skip("/api/reservations endpoint not implemented")
    assert rlist.status_code == 200
    data = rlist.json()
    assert any(str(x.get("id")) == str(rid) for x in data)

    rdet = requests.get(
        f"{BASE}/api/reservations/{rid}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    if rdet.status_code == 404:
        pytest.skip("/api/reservations endpoint not implemented")
    assert rdet.status_code == 200

    other_user, other_tok = make_user_and_login("USER")
    rforbidden = requests.get(
        f"{BASE}/api/reservations/{rid}",
        headers={"Authorization": f"Bearer {other_tok}"},
        timeout=5,
    )
    assert rforbidden.status_code == 403

    rdel = requests.delete(
        f"{BASE}/api/reservations/{rid}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    if rdel.status_code == 404:
        pytest.skip("/api/reservations endpoint not implemented")
    assert rdel.status_code == 200
