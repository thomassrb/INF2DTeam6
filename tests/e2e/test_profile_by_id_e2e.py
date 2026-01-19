import requests
import pytest

BASE = "http://localhost:8000"


def test_profile_by_id_access_control_e2e(server_process, make_user_and_login):
    _, token = make_user_and_login("USER")
    headers = {"Authorization": f"Bearer {token}"}

    r_me = requests.get(f"{BASE}/api/profile", headers=headers, timeout=5)
    if r_me.status_code in (404, 405):
        pytest.skip("/api/profile endpoint not implemented")
    assert r_me.status_code == 200, r_me.text

    my_id = r_me.json().get("id")
    assert my_id is not None

    r_self = requests.get(f"{BASE}/api/profile/{my_id}", headers=headers, timeout=5)
    if r_self.status_code in (404, 405):
        pytest.skip("/api/profile/{user_id} endpoint not implemented")
    assert r_self.status_code == 200, r_self.text

    other_user, other_tok = make_user_and_login("USER")
    r_other = requests.get(
        f"{BASE}/api/profile/{my_id}",
        headers={"Authorization": f"Bearer {other_tok}"},
        timeout=5,
    )
    assert r_other.status_code == 403

    _, admin_tok = make_user_and_login("ADMIN")
    r_admin = requests.get(
        f"{BASE}/api/profile/{my_id}",
        headers={"Authorization": f"Bearer {admin_tok}"},
        timeout=5,
    )
    assert r_admin.status_code == 200, r_admin.text
    assert r_admin.json().get("id") == my_id
