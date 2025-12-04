import requests

BASE = "http://localhost:8000"


def test_vehicle_crud_and_duplicate_protection(server_process, make_user_and_login):
    username, token = make_user_and_login("USER")

    # Eerst gaan we een voertiug aanmaken
    vpayload = {"licenseplate": "DMX-123", "name": "Amarok"}
    rcreate = requests.post(f"{BASE}/vehicles", json=vpayload, headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert rcreate.status_code in (200, 201), rcreate.text
    vid = rcreate.json().get("vehicle", {}).get("id")

    # License plate duplicaten voor dezelfde user, dan zou er een 409 error moeten komen
    rdup = requests.post(f"{BASE}/vehicles", json=vpayload, headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert rdup.status_code == 409

    # list de users voertuigen
    rlist = requests.get(f"{BASE}/vehicles", headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert rlist.status_code == 200
    vehicles = rlist.json()
    assert any(v.get("id") == vid for v in vehicles)

    # voertuig naam updaten
    rupd = requests.put(
        f"{BASE}/vehicles/{vid}",
        json={"name": "Amarok twee"},
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    assert rupd.status_code == 200

    # voertuig details getten
    rget = requests.get(f"{BASE}/vehicles/{vid}", headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert rget.status_code == 200
    assert rget.json().get("vehicle", {}).get("name") == "Amarok twee"

    # Deleten van voertuig
    rdel = requests.delete(f"{BASE}/vehicles/{vid}", headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert rdel.status_code == 200

    # Ensure dat die weg is
    rlist2 = requests.get(f"{BASE}/vehicles", headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert rlist2.status_code == 200
    assert not any(v.get("id") == vid for v in rlist2.json())
