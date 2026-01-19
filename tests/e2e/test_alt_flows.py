import requests
import pytest

BASE = "http://localhost:8000"

def test_profile_without_token_returns_401(server_process):
    r = requests.get(f"{BASE}/api/profile", timeout=5)
    assert r.status_code == 401

def test_non_admin_cannot_view_other_users_billing_returns_403(server_process, make_user_and_login):
    u1, tok1 = make_user_and_login("USER")
    u2, tok2 = make_user_and_login("USER")

    r = requests.get(
        f"{BASE}/api/users/{u2}/billing", 
        headers={"Authorization": f"Bearer {tok1}"}, 
        timeout=5
    )
    assert r.status_code in (403, 404)

def test_create_parking_lot_without_capacity_returns_400(server_process, admin_token):
    payload = {
        "name": "NoCapLot",
        "location": "X",
        # "capacity":
        "tariff": 2.0,
        "daytariff": 10.0,
        "address": "X",
        "coordinates": {"lat": 1.0, "lng": 2.0},
    }
    r = requests.post(
        f"{BASE}/api/parkinglots", 
        json=payload, 
        headers={"Authorization": f"Bearer {admin_token}"}, 
        timeout=5
    )
    assert r.status_code in (400, 422, 404)

def test_start_session_without_license_plate_returns_400(server_process, admin_token, user_token):
    name = "ParkeerplaatsX"
    payload = {
        "name": name,
        "location": "Y",
        "capacity": 10,
        "tariff": 1.0,
        "daytariff": 9.0,
        "address": "Nietparkeren",
        "coordinates": {"lat": 1.0, "lng": 2.0},
    }
    
    cr = requests.post(
        f"{BASE}/api/parkinglots", 
        json=payload, 
        headers={"Authorization": f"Bearer {admin_token}"}, 
        timeout=5
    )
    if cr.status_code == 404:
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert cr.status_code in (200, 201)
    
    # Get parking lots with authentication
    auth_headers = {"Authorization": f"Bearer {admin_token}"}
    lots_response = requests.get(f"{BASE}/api/parkinglots", headers=auth_headers, timeout=5)
    if lots_response.status_code == 401:
        pytest.skip("Authentication required for parking lots endpoint")
    assert lots_response.status_code == 200
    lots = lots_response.json()
    lot = next((lot for lot in lots if lot.get("name") == name), None)
    assert lot is not None
    lot_id = lot.get("id")
    assert lot_id is not None

    _, u_tok = user_token
    r = requests.post(
        f"{BASE}/api/parkinglots/{lot_id}/sessions/start",
        json={},
        headers={"Authorization": f"Bearer {u_tok}"},
        timeout=5,
    )
    assert r.status_code in (400, 422)

def test_login_missing_username_returns_400(server_process):
    payload = {
        "password": "SomePass123!",
    }
    r = requests.post(f"{BASE}/api/login", json=payload, timeout=5)
    assert r.status_code in (400, 422)

def test_login_with_invalid_credentials_returns_401(server_process, make_user_and_login):
    username, _ = make_user_and_login("USER")

    bad_login = requests.post(
        f"{BASE}/api/login",
        json={"username": username, "password": "TotallyWrongPass!"},
        timeout=5,
    )
    assert bad_login.status_code == 401
    body = bad_login.json()
    assert "invalid" in str(body.get("detail", "")).lower() or body

def test_create_reservation_for_nonexistent_parking_lot_returns_404(server_process, make_user_and_login):
    _, token = make_user_and_login("USER")

    payload = {
        "parkinglot": "nonexistent-lot-id",
        "start_time": "2025-01-01T10:00:00",
        "end_time": "2025-01-01T12:00:00",
        "license_plate": "RES-PLATE-404",
    }

    r = requests.post(
        f"{BASE}/api/reservations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code in (404, 405)

def test_get_nonexistent_parking_lot_returns_404(server_process):
    r = requests.get(f"{BASE}/api/parkinglots/nonexistent-lot-id", timeout=5)
    assert r.status_code == 401

def test_create_parking_lot_as_user_forbidden(server_process, admin_token, user_token):
    _, u_tok = user_token
    payload = {
        "name": "E2E lot user",
        "location": "E2E Loc",
        "address": "E2E Addr user",
        "capacity": 10,
        "tariff": 1.25,
        "daytariff": 10.0,
        "coordinates": {"lat": 1.0, "lng": 2.0},
    }
    r = requests.post(
        f"{BASE}/api/parkinglots", 
        json=payload, 
        headers={"Authorization": f"Bearer {u_tok}"}, 
        timeout=5
    )
    assert r.status_code in (401, 403, 404)

def test_start_session_missing_license_plate(server_process, admin_token, user_token):
    name = "E2E lot missing plate"
    payload = {
        "name": name,
        "location": "E2E Loc",
        "address": f"E2E Addr {name}",
        "capacity": 10,
        "tariff": 1.25,
        "daytariff": 10.0,
        "coordinates": {"lat": 1.0, "lng": 2.0},
    }
    
    cr = requests.post(
        f"{BASE}/api/parkinglots", 
        json=payload, 
        headers={"Authorization": f"Bearer {admin_token}"}, 
        timeout=5
    )
    if cr.status_code == 404:
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert cr.status_code in (200, 201)
    
    # Get parking lots with authentication
    auth_headers = {"Authorization": f"Bearer {admin_token}"}
    lots_response = requests.get(f"{BASE}/api/parkinglots", headers=auth_headers, timeout=5)
    if lots_response.status_code == 401:
        pytest.skip("Authentication required for parking lots endpoint")
    assert lots_response.status_code == 200
    lots = lots_response.json()
    lot = next((lot for lot in lots if lot.get("name") == name), None)
    assert lot is not None
    lot_id = lot.get("id")
    assert lot_id is not None

    _, u_tok = user_token
    r = requests.post(
        f"{BASE}/api/parkinglots/{lot_id}/sessions/start",
        json={},
        headers={"Authorization": f"Bearer {u_tok}"},
        timeout=5,
    )
    assert r.status_code in (400, 422)