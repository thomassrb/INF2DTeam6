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


def test_logout_invalidates_token(client: TestClient):
    username = f"it_{uuid.uuid4().hex[:8]}"
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
            "role": "USER",
        },
    )
    assert r.status_code in (200, 201), r.text

    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json().get("session_token")
    assert token

    headers = {"Authorization": f"Bearer {token}"}

    r = client.get("/api/profile", headers=headers)
    assert r.status_code == 200, r.text

    r = client.post("/api/logout", headers=headers)
    if r.status_code in (404, 405):
        pytest.skip("/api/logout endpoint not implemented")
    assert r.status_code == 200, r.text

    r = client.get("/api/profile", headers=headers)
    assert r.status_code == 401
