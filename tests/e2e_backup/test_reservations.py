import requests

BASE = "http://localhost:8000"


def test_user_can_create_and_view_and_delete_reservation(server_process, make_user_and_login, admin_token):
    # als admin nieuwe parking lot createn
    payload = {
        "name": "Gereserveerdeparking",
        "location": "Wijnhaven_parking",
        "capacity": 50,
        "tariff": 2.0,
        "daytariff": 15.0,
        "address": "Wijnhaven 106",
        "coordinates": [4.0, 5.0],
    }
    cr = requests.post(f"{BASE}/parking-lots", json=payload, headers={"Authorization": f"Bearer {admin_token}"}, timeout=5)
    assert cr.status_code in (200, 201)

    lots = requests.get(f"{BASE}/parking-lots", timeout=5).json()
    lot_id = next((lid for lid, lot in lots.items() if lot.get("name") == "Gereserveerdeparking"), None)
    assert lot_id

    username, token = make_user_and_login("USER")

    # reserveren parking
    res_payload = {
        "parkinglot": lot_id,
        "license_plate": "DMX-001",
        "start_time": "2025-01-01 10:00:00",
        "end_time": "2025-01-01 12:00:00",
        "user": username,
    }
    r = requests.post(
        f"{BASE}/reservations",
        json=res_payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert r.status_code in (200, 201), r.text
    rid = r.json().get("reservation", {}).get("id") or r.json().get("id")
    assert rid

    # list met reservations, zou de nieuwe er bij moeten stoppen
    rlist = requests.get(
        f"{BASE}/reservations",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert rlist.status_code == 200
    data = rlist.json()
    assert rid in data

    rdet = requests.get(
        f"{BASE}/reservations/{rid}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert rdet.status_code == 200

    # andere gebruiker zou niet hier bij moeten kunnen
    other_user, other_tok = make_user_and_login("USER")
    rforbidden = requests.get(
        f"{BASE}/reservations/{rid}",
        headers={"Authorization": f"Bearer {other_tok}"},
        timeout=5,
    )
    assert rforbidden.status_code == 403

    # deleeten van de reservation
    rdel = requests.delete(
        f"{BASE}/reservations/{rid}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert rdel.status_code == 200
