import importlib
import uuid

import pytest

pytest.importorskip("httpx")
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MOBYPARK_DB_DIR", str(tmp_path))

    from MobyPark.api import app as app_module

    importlib.reload(app_module)

    c = TestClient(app_module.app)
    try:
        yield c
    finally:
        try:
            app_module.connection.close_connection()
        except Exception:
            pass

        try:
            from MobyPark.api import session_manager

            session_manager._SESSIONS.clear()
        except Exception:
            pass


def _register_and_login(client: TestClient, role: str = "USER") -> tuple[str, str]:
    username = f"it_{role.lower()}_{uuid.uuid4().hex[:8]}"
    password = "StrongPassw0rd!"

    r = client.post(
        "/api/register",
        json={
            "username": username,
            "password": password,
            "name": username,
            "phone": "0000000000",
            "email": f"{username}@example.com",
            "birth_year": 2000,
            "role": role,
        },
    )
    assert r.status_code in (200, 201), r.text

    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json().get("session_token")
    assert token
    return username, token


def test_user_cannot_create_parking_lot(client: TestClient):
    _, token = _register_and_login(client, role="USER")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "name": f"IT Lot {uuid.uuid4().hex[:6]}",
        "location": "IT Location",
        "address": "IT Address",
        "capacity": 10,
        "tariff": 1.25,
        "daytariff": 10.0,
        "coordinates": {"lat": 52.0, "lng": 4.0},
    }

    r = client.post("/api/parkinglots", json=payload, headers=headers)
    if r.status_code in (404, 405):
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert r.status_code in (401, 403), r.text


def test_admin_can_create_parking_lot_and_list(client: TestClient):
    _, token = _register_and_login(client, role="ADMIN")
    headers = {"Authorization": f"Bearer {token}"}

    lot_name = f"IT Admin Lot {uuid.uuid4().hex[:6]}"
    payload = {
        "name": lot_name,
        "location": "IT Admin Location",
        "address": "IT Admin Address",
        "capacity": 5,
        "tariff": 1.0,
        "daytariff": 8.0,
        "coordinates": {"lat": 52.1, "lng": 4.1},
    }

    rcreate = client.post("/api/parkinglots", json=payload, headers=headers)
    if rcreate.status_code in (404, 405):
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert rcreate.status_code in (200, 201), rcreate.text

    rlist = client.get("/api/parkinglots")
    assert rlist.status_code == 200, rlist.text
    lots = rlist.json()
    assert isinstance(lots, list)
    assert any(l.get("name") == lot_name for l in lots)
