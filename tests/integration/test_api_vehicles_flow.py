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


def test_vehicle_create_list_duplicate(client: TestClient):
    _, token = _register_and_login(client, role="ADMIN")
    headers = {"Authorization": f"Bearer {token}"}

    plate = f"IT-{uuid.uuid4().hex[:6].upper()}"
    payload = {
        "licenseplate": plate,
        "name": "IntegrationTruck",
        "make": "TestMake",
        "model": "TestModel",
        "color": "Black",
        "year": 2020,
        "created_at": datetime.utcnow().isoformat(),
    }

    rcreate = client.post("/api/vehicles", json=payload, headers=headers)
    if rcreate.status_code in (404, 405):
        pytest.skip("/api/vehicles endpoint not implemented")
    assert rcreate.status_code in (200, 201), rcreate.text

    body = rcreate.json()
    vehicle = body.get("vehicle") or {}
    assert vehicle.get("license_plate") == plate

    rlist = client.get("/api/vehicles", headers=headers)
    if rlist.status_code in (404, 405):
        pytest.skip("GET /api/vehicles endpoint not implemented")
    assert rlist.status_code == 200, rlist.text
    vehicles = rlist.json()
    assert isinstance(vehicles, list)
    assert any(v.get("licenseplate") == plate or v.get("license_plate") == plate for v in vehicles)

    rdup = client.post("/api/vehicles", json=payload, headers=headers)
    assert rdup.status_code in (400, 409)
