import time

import requests


BASE = "http://localhost:8000"


def test_admin_can_create_and_list_parkinglot_via_parkinglots_endpoint(server_process, admin_token):
    payload = {
        "name": f"E2E Lot {int(time.time())}",
        "location": "E2E City",
        "capacity": 5,
        "tariff": 2.0,
        "daytariff": 10.0,
        "address": f"E2E Address {int(time.time())}",
        "coordinates": {"lng": 4.0, "lat": 52.0},
    }

    r = requests.post(
        f"{BASE}/api/parkinglots",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5,
    )
    assert r.status_code in (200, 201), r.text

    rlist = requests.get(
        f"{BASE}/api/parkinglots",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5
    )
    assert rlist.status_code == 200
    lots = rlist.json()
    assert isinstance(lots, list)
    assert any(l.get("name") == payload["name"] for l in lots)


def test_non_admin_cannot_create_parkinglot(server_process, user_token):
    _, token = user_token
    payload = {
        "name": f"E2E Lot Forbidden {int(time.time())}",
        "location": "E2E City",
        "capacity": 5,
        "tariff": 2.0,
        "daytariff": 10.0,
        "address": f"E2E Address Forbidden {int(time.time())}",
        "coordinates": {"lng": 4.0, "lat": 52.0},
    }

    r = requests.post(
        f"{BASE}/api/parkinglots",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 403
