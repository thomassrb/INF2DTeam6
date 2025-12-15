import requests
import time

BASE = "http://localhost:8000"

def test_profile_without_token_returns_401(server_process):
    r = requests.get(f"{BASE}/profile", timeout=5)
    assert r.status_code == 401

def test_non_admin_cannot_view_other_users_billing_returns_403(server_process, make_user_and_login):
    u1, tok1 = make_user_and_login("USER")
    u2, tok2 = make_user_and_login("USER")

    r = requests.get(f"{BASE}/billing/{u2}", headers={"Authorization": f"Bearer {tok1}"}, timeout=5)
    assert r.status_code == 403



def test_create_parking_lot_without_capacity_returns_400(server_process, admin_token):
    payload = {
        "name": "NoCapLot",
        "location": "X",
        # "capacity": Bewust niet toegevoegd
        "tariff": 2.0,
        "daytariff": 10.0,
        "address": "X",
        "coordinates": [1.0, 2.0],
    }
    r = requests.post(f"{BASE}/parking-lots", json=payload, headers={"Authorization": f"Bearer {admin_token}"}, timeout=5)
    assert r.status_code == 400

def test_start_session_without_license_plate_returns_400(server_process, admin_token, user_token):
    # Test die een parking sessie start zonder licence plate en returned een HTTP 400
    name = f"ParkeerplaatsX-{int(time.time())}"
    payload = {
        "name": name,
        "location": "Y",
        "capacity": 10,
        "tariff": 1.0,
        "daytariff": 9.0,
        "address": "Nietparkeren",
        "coordinates": [1.0, 2.0],
    }
    cr = requests.post(
        f"{BASE}/parking-lots", 
        json=payload, 
        headers={"Authorization": f"Bearer {admin_token}"}, 
        timeout=5
    )
    assert cr.status_code in (200, 201)
    lot_id = cr.json()["id"]

    _, u_tok = user_token
    r = requests.post(
        f"{BASE}/parking-lots/{lot_id}/sessions/start",
        json={},
        headers={"Authorization": f"Bearer {u_tok}"},
        timeout=5,
    )
    assert r.status_code == 400

def test_login_missing_username_returns_400(server_process):
    payload = {
        # "username" bewust weggelaten
        "password": "SomePass123!",
    }
    r = requests.post(f"{BASE}/login", json=payload, timeout=5)
    assert r.status_code == 400
    body = r.json()
    # login handler stuurt { "error": "...", "field": "username" }
    assert body.get("field") == "username"


def test_login_with_invalid_credentials_returns_401(server_process, make_user_and_login):
    # Eerst een geldige user aanmaken
    username, _ = make_user_and_login("USER")

    # Daarna proberen in te loggen met een fout wachtwoord
    bad_login = requests.post(
        f"{BASE}/login",
        json={"username": username, "password": "TotallyWrongPass!"},
        timeout=5,
    )
    assert bad_login.status_code == 401
    body = bad_login.json()
    assert body.get("error") == "Invalid credentials"


def test_create_reservation_for_nonexistent_parking_lot_returns_404(server_process, make_user_and_login):
    username, token = make_user_and_login("USER")

    payload = {
        # Deze parkinglot id bestaat niet in de data
        "parkinglot": "nonexistent-lot-id",
        "user": username,
        "licenseplate": "RES-PLATE-404",
    }

    r = requests.post(
        f"{BASE}/reservations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 404
    body = r.json()
    assert "error" in body, f"Expected 'error' in response, got: {body}"
    assert body["error"] == "Parking lot not found"
    assert "field" in body, f"Expected 'field' in response, got: {body}"
    assert body["field"] == "parkinglot"


def test_get_nonexistent_parking_lot_returns_404(server_process):
    r = requests.get(f"{BASE}/parking-lots/nonexistent-lot-id", timeout=5)
    assert r.status_code == 404
    body = r.json()
    # The error is nested inside a 'detail' key
    assert "detail" in body, f"Expected 'detail' in response, got: {body}"
    if isinstance(body["detail"], dict):
        # New format: {"detail": {"error": "message"}}
        assert "error" in body["detail"], f"Expected 'error' in detail, got: {body['detail']}"
        assert body["detail"]["error"] == "Parking lot not found"
    else:
        # Fallback in case the format changes in the future
        assert body.get("detail") == "Parking lot not found" or body.get("error") == "Parking lot not found"