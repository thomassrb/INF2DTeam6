import requests
import uuid

BASE = "http://localhost:8000"


def test_profile_without_token_returns_401(server_process):
    r = requests.get(f"{BASE}/profile", timeout=5)
    assert r.status_code == 401


def test_non_admin_cannot_view_other_users_billing_returns_403(server_process, make_user_and_login):
    u1, tok1 = make_user_and_login("USER")
    u2, tok2 = make_user_and_login("USER")

    r = requests.get(
        f"{BASE}/billing/{u2.username}", 
        headers={"Authorization": f"Bearer {tok1}"}, 
        timeout=5
    )
    assert r.status_code == 403


def test_create_parking_lot_without_capacity_returns_400(server_process, admin_token):
    payload = {
        "name": "NoCapLot",
        "location": "X",
        # "capacity": mist bewust
        "tariff": 2.0,
        "daytariff": 10.0,
        "address": "X",
        "coordinates": [1.0, 2.0],
    }
    r = requests.post(
        f"{BASE}/parking-lots", 
        json=payload, 
        headers={"Authorization": f"Bearer {admin_token}"}, 
        timeout=5
    )
    assert r.status_code == 400


def test_start_session_without_license_plate_returns_400(server_process, admin_token, user_token):
    name = "ParkeerplaatsX"
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
    
    lot_id = cr.json().get("id")
    assert lot_id

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
        # "username" mist bewust
        "password": "SomePass123!",
    }
    r = requests.post(f"{BASE}/login", json=payload, timeout=5)
    assert r.status_code == 422
    body = r.json()
    assert any(error.get("loc") and "username" in error.get("loc") for error in body.get("detail", []))


def test_login_with_invalid_credentials_returns_401(server_process, make_user_and_login):
    user, _ = make_user_and_login("USER")

    bad_login = requests.post(
        f"{BASE}/login",
        json={"username": user.username, "password": "TotallyWrongPass!"},
        timeout=5,
    )
    assert bad_login.status_code == 401
    body = bad_login.json()
    assert body.get("detail") == "Invalid credentials"


def test_create_reservation_for_nonexistent_parking_lot_returns_404(server_process, make_user_and_login):
    user, token = make_user_and_login("USER")

    payload = {
        "parkinglot": str(uuid.uuid4()),
        "licenseplate": "RES-PLATE-404",
        "start": "2023-01-01T10:00:00",
        "end": "2023-01-01T12:00:00"
    }

    r = requests.post(
        f"{BASE}/reservations",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code == 404
    body = r.json()
    assert "not found" in body.get("detail", "").lower()


def test_get_nonexistent_parking_lot_returns_404(server_process):
    non_existent_id = str(uuid.uuid4())
    r = requests.get(f"{BASE}/parking-lots/{non_existent_id}", timeout=5)
    assert r.status_code == 404
    body = r.json()
    assert "not found" in body.get("detail", "").lower()