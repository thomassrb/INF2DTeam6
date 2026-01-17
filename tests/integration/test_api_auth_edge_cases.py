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


def test_register_duplicate_username_returns_409(client: TestClient):
    username = f"dup_{uuid.uuid4().hex[:8]}"
    payload = {
        "username": username,
        "password": "Passw0rd!",
        "name": username,
        "phone": "0000000000",
        "email": f"{username}@example.com",
        "birth_year": 2000,
        "role": "USER",
    }

    r1 = client.post("/api/register", json=payload)
    assert r1.status_code == 201, r1.text

    # same username, different email still conflicts (username unique)
    payload2 = dict(payload)
    payload2["email"] = f"{username}_2@example.com"
    r2 = client.post("/api/register", json=payload2)
    assert r2.status_code == 409, r2.text


def test_login_invalid_credentials_returns_401(client: TestClient):
    r = client.post("/api/login", json={"username": "nope", "password": "nope"})
    assert r.status_code == 401


def test_login_missing_field_returns_422(client: TestClient):
    r = client.post("/api/login", json={"password": "x"})
    assert r.status_code == 422
