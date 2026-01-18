import time

import requests
import pytest

BASE = "http://localhost:8000"


def test_vehicle_duplicate_and_delete_permissions_e2e(server_process, make_user_and_login):
    _, user_tok = make_user_and_login("USER")
    plate = f"E2E-VEH-{int(time.time())}"
    payload = {
        "licenseplate": plate,
        "name": "E2E Vehicle",
        "make": "E2E",
        "model": "Model",
        "color": "Black",
        "year": 2020,
        "created_at": "2025-01-01 00:00:00",
    }

    r1 = requests.post(
        f"{BASE}/api/vehicles",
        json=payload,
        headers={"Authorization": f"Bearer {user_tok}"},
        timeout=5,
    )
    if r1.status_code in (404, 405):
        pytest.skip("/api/vehicles endpoint not implemented")
    assert r1.status_code in (200, 201), r1.text

    rdup = requests.post(
        f"{BASE}/api/vehicles",
        json=payload,
        headers={"Authorization": f"Bearer {user_tok}"},
        timeout=5,
    )
    assert rdup.status_code in (400, 409)

    try:
        body = r1.json()
    except Exception:
        body = {}
    vid = (body.get("vehicle") or {}).get("id") or body.get("id")

    if not vid:
        rlist = requests.get(
            f"{BASE}/api/vehicles",
            headers={"Authorization": f"Bearer {user_tok}"},
            timeout=5,
        )
        assert rlist.status_code == 200, rlist.text
        vehicles = rlist.json()
        v = next((x for x in vehicles if x.get("licenseplate") == plate or x.get("license_plate") == plate), None)
        assert v is not None
        vid = v.get("id")

    assert vid

    _, other_tok = make_user_and_login("USER")
    rforbidden = requests.delete(
        f"{BASE}/api/vehicles/{vid}",
        headers={"Authorization": f"Bearer {other_tok}"},
        timeout=5,
    )
    assert rforbidden.status_code == 403

    rdel = requests.delete(
        f"{BASE}/api/vehicles/{vid}",
        headers={"Authorization": f"Bearer {user_tok}"},
        timeout=5,
    )
    assert rdel.status_code == 200, rdel.text
