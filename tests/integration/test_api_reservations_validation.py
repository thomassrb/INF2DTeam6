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


def test_reservation_end_before_start_returns_400(client: TestClient):
    username, user_token = _register_and_login(client, role="USER")
    _, admin_token = _register_and_login(client, role="ADMIN")

    lot_id = _create_parking_lot(client, admin_token)

    plate = f"IT-RES-{uuid.uuid4().hex[:6].upper()}"
    _create_vehicle(client, user_token, plate)

    r = client.post(
        "/api/reservations",
        json={
            "parkinglot": lot_id,
            "license_plate": plate,
            "start_time": "2025-01-01 12:00:00",
            "end_time": "2025-01-01 10:00:00",
            "user": username,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    if r.status_code == 405:
        pytest.skip("/api/reservations endpoint not implemented")
    assert r.status_code == 400


def test_reservation_missing_vehicle_returns_404(client: TestClient):
    username, user_token = _register_and_login(client, role="USER")
    _, admin_token = _register_and_login(client, role="ADMIN")

    lot_id = _create_parking_lot(client, admin_token)

    r = client.post(
        "/api/reservations",
        json={
            "parkinglot": lot_id,
            "license_plate": "NO-SUCH-PLATE",
            "start_time": "2025-01-01 10:00:00",
            "end_time": "2025-01-01 12:00:00",
            "user": username,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    if r.status_code == 405:
        pytest.skip("/api/reservations endpoint not implemented")
    assert r.status_code == 404


def test_reservation_missing_parking_lot_returns_404(client: TestClient):
    username, user_token = _register_and_login(client, role="USER")

    plate = f"IT-RES-{uuid.uuid4().hex[:6].upper()}"
    _create_vehicle(client, user_token, plate)

    r = client.post(
        "/api/reservations",
        json={
            "parkinglot": "999999",
            "license_plate": plate,
            "start_time": "2025-01-01 10:00:00",
            "end_time": "2025-01-01 12:00:00",
            "user": username,
        },
        headers={"Authorization": f"Bearer {user_token}"},
    )
    if r.status_code == 405:
        pytest.skip("/api/reservations endpoint not implemented")
    assert r.status_code == 404
