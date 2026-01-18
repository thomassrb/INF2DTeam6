import importlib
import uuid
from datetime import datetime

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


def _create_parking_lot(client: TestClient, admin_token: str) -> str:
    payload = {
        "name": "IT Lot",
        "location": "IT Loc",
        "address": f"IT Address {uuid.uuid4().hex}",
        "capacity": 10,
        "tariff": 1.25,
        "daytariff": 10.0,
        "coordinates": {"lat": 4.0, "lng": 5.0},
    }
    r = client.post(
        "/api/parkinglots",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if r.status_code in (404, 405):
        pytest.skip("/api/parkinglots endpoint not implemented")
    assert r.status_code in (200, 201), r.text

    rlist = client.get("/api/parkinglots")
    assert rlist.status_code == 200, rlist.text
    lot = next((l for l in rlist.json() if l.get("address") == payload["address"]), None)
    assert lot is not None
    return str(lot.get("id"))


def _create_vehicle(client: TestClient, token: str, plate: str):
    payload = {
        "licenseplate": plate,
        "name": "IntegrationCar",
        "make": "TestMake",
        "model": "TestModel",
        "color": "Black",
        "year": 2020,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }
    r = client.post(
        "/api/vehicles",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    if r.status_code in (404, 405):
        pytest.skip("/api/vehicles endpoint not implemented")
    assert r.status_code in (200, 201, 409), r.text


def test_start_session_twice_returns_409(client: TestClient):
    _, admin_token = _register_and_login(client, role="ADMIN")
    _, user_token = _register_and_login(client, role="USER")

    lot_id = _create_parking_lot(client, admin_token)

    plate = f"IT-SES-{uuid.uuid4().hex[:6].upper()}"
    _create_vehicle(client, user_token, plate)

    r1 = client.post(
        f"/api/parkinglots/{lot_id}/sessions/start",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    if r1.status_code in (404, 405):
        pytest.skip("sessions endpoints not implemented")
    assert r1.status_code == 200, r1.text

    r2 = client.post(
        f"/api/parkinglots/{lot_id}/sessions/start",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert r2.status_code == 409


def test_stop_without_start_returns_409(client: TestClient):
    _, admin_token = _register_and_login(client, role="ADMIN")
    _, user_token = _register_and_login(client, role="USER")

    lot_id = _create_parking_lot(client, admin_token)

    plate = f"IT-SES-{uuid.uuid4().hex[:6].upper()}"
    _create_vehicle(client, user_token, plate)

    r = client.post(
        f"/api/parkinglots/{lot_id}/sessions/stop",
        json={"license_plate": plate},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    if r.status_code in (404, 405):
        pytest.skip("sessions endpoints not implemented")
    assert r.status_code == 409


def test_start_session_missing_plate_returns_400_or_422(client: TestClient):
    _, admin_token = _register_and_login(client, role="ADMIN")
    _, user_token = _register_and_login(client, role="USER")

    lot_id = _create_parking_lot(client, admin_token)

    r = client.post(
        f"/api/parkinglots/{lot_id}/sessions/start",
        json={},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    if r.status_code in (404, 405):
        pytest.skip("sessions endpoints not implemented")
    assert r.status_code in (400, 422)
