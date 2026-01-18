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


def test_profile_by_id_access_control(client: TestClient):
    _, user_token = _register_and_login(client, role="USER")
    _, other_token = _register_and_login(client, role="USER")
    _, admin_token = _register_and_login(client, role="ADMIN")

    r_me = client.get("/api/profile", headers={"Authorization": f"Bearer {user_token}"})
    assert r_me.status_code == 200, r_me.text
    my_id = r_me.json().get("id")
    assert my_id is not None

    r_other = client.get("/api/profile", headers={"Authorization": f"Bearer {other_token}"})
    assert r_other.status_code == 200, r_other.text
    other_id = r_other.json().get("id")
    assert other_id is not None

    # User can fetch their own profile by id
    r = client.get(f"/api/profile/{my_id}", headers={"Authorization": f"Bearer {user_token}"})
    if r.status_code in (404, 405):
        pytest.skip("/api/profile/{user_id} endpoint not implemented")
    assert r.status_code == 200, r.text
    assert r.json().get("id") == my_id

    # User cannot fetch someone else's profile by id
    r = client.get(f"/api/profile/{other_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code in (403, 404)

    # Admin can fetch someone else's profile by id
    r = client.get(f"/api/profile/{other_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200, r.text
    assert r.json().get("id") == other_id
