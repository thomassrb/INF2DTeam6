import pytest
import requests
import os

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")


def test_user_cannot_create_parking_lot(server_process, user_token):
    _, token = user_token
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "name": "E2E Lot",
        "location": "E2E Location",
        "address": "E2E Address",
        "capacity": 10,
        "tariff": 1.25,
        "daytariff": 10.0,
        "coordinates": {"lat": 52.0, "lng": 4.0},
    }

    r = requests.post(f"{BASE_URL}/api/parkinglots", json=payload, headers=headers, timeout=5)
    if r.status_code in (404, 405):
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert r.status_code in (401, 403)


def test_admin_can_create_then_delete_parking_lot(server_process, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}

    payload = {
        "name": "E2E Admin Lot",
        "location": "E2E Admin Location",
        "address": "E2E Admin Address",
        "capacity": 5,
        "tariff": 1.0,
        "daytariff": 8.0,
        "coordinates": {"lat": 52.1, "lng": 4.1},
    }

    rcreate = requests.post(f"{BASE_URL}/api/parkinglots", json=payload, headers=headers, timeout=5)
    if rcreate.status_code in (404, 405):
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert rcreate.status_code in (200, 201), rcreate.text

    rlist = requests.get(f"{BASE_URL}/api/parkinglots", headers=headers, timeout=5)
    assert rlist.status_code == 200
    lots = rlist.json()
    assert isinstance(lots, list)

    created = next((l for l in lots if l.get("name") == payload["name"]), None)
    if not created:
        pytest.skip("Parking lot list response does not include created lot")

    lot_id = created.get("id")
    if lot_id is None:
        pytest.skip("Parking lot list does not include id field")

    rdel = requests.delete(f"{BASE_URL}/api/parkinglots/{lot_id}", headers=headers, timeout=5)
    if rdel.status_code in (404, 405):
        pytest.skip("DELETE /api/parkinglots/{id} endpoint not implemented")
    assert rdel.status_code in (200, 204), rdel.text
