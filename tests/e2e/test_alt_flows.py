import requests

BASE = "http://localhost:8000"

def test_401_profile_without_token(server_process):
    r = requests.get(f"{BASE}/profile", timeout=5)
    assert r.status_code == 401

def test_403_billing_for_other_user_as_non_admin(server_process, make_user_and_login):
    u1, tok1 = make_user_and_login("USER")
    u2, tok2 = make_user_and_login("USER")

    r = requests.get(f"{BASE}/billing/{u2}", headers={"Authorization": f"Bearer {tok1}"}, timeout=5)
    assert r.status_code == 403

def test_400_parking_lot_missing_capacity(server_process, admin_token):
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

def test_400_session_start_missing_plate(server_process, admin_token, user_token):
    # Test die een parking sessie start zonder licence plate en returned een HTTP 400
    # De  `_, u_tok = user_token` unpacked de username en token pair en returned het by fixture
    # De underscore (_) wordt gebruikt om de eerste value (the username) te ignoren, keeping alleen de token (`u_tok`)
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
    cr = requests.post(f"{BASE}/parking-lots", json=payload, headers={"Authorization": f"Bearer {admin_token}"}, timeout=5)
    assert cr.status_code in (200, 201)

    lots = requests.get(f"{BASE}/parking-lots", timeout=5).json()
    lot_id = next((lid for lid, lot in lots.items() if lot.get("name") == name), None)
    assert lot_id

    _, u_tok = user_token
    r = requests.post(
        f"{BASE}/parking-lots/{lot_id}/sessions/start",
        json={},
        headers={"Authorization": f"Bearer {u_tok}"},
        timeout=5,
    )
    assert r.status_code == 400