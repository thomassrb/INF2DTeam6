import pytest
import requests
import os

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")


def test_profile_requires_auth(server_process):
    r = requests.get(f"{BASE_URL}/api/profile", timeout=5)
    assert r.status_code in (401, 403)


def test_login_logout_profile_flow(server_process, make_user_and_login):
    _, token = make_user_and_login("USER")
    headers = {"Authorization": f"Bearer {token}"}

    rprofile = requests.get(f"{BASE_URL}/api/profile", headers=headers, timeout=5)
    assert rprofile.status_code == 200
    data = rprofile.json()
    assert isinstance(data, dict)
    assert data.get("username")

    rlogout = requests.post(f"{BASE_URL}/api/logout", headers=headers, timeout=5)
    if rlogout.status_code in (404, 405):
        pytest.skip("/api/logout endpoint not implemented")
    assert rlogout.status_code in (200, 204), rlogout.text

    rprofile2 = requests.get(f"{BASE_URL}/api/profile", headers=headers, timeout=5)
    assert rprofile2.status_code in (401, 403)
