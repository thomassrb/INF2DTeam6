import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
SERVER_ENTRY = Path(__file__).resolve().parents[2] / "MobyPark" / "api" / "server.py" # verkeerd path..
DATA_DIR = Path(__file__).resolve().parents[2] / "MobyPark-api-data"

#  ---
def wait_for_server(url: str, timeout_sec: int = 20) -> None:
    start = time.time()
    last_err = None
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(url, timeout=1)
            if r.status_code in (200, 204, 302):
                return
        except Exception as e:
            last_err = e
        time.sleep(0.3)
    raise RuntimeError(f"Server not ready at {url}: {last_err}")


@pytest.fixture(scope="session", autouse=True)
def server_process():
    # API starten als subprocess op de achtergrond
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "pdata").mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["MOBYPARK_DATA_DIR"] = str(DATA_DIR)

    proc = subprocess.Popen(
        [sys.executable, "-u", str(SERVER_ENTRY)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(SERVER_ENTRY.parent),
        env=env,
    )
    try:
        wait_for_server(f"{BASE_URL}/")
        yield proc
    finally:
        # Terminate de server
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture()
def make_user_and_login():
    def _make(role: str = "USER"):
        import uuid

        username = f"e2e_{role.lower()}_{uuid.uuid4().hex[:8]}"
        password = "E2ePassw0rd!"
        # Registeren
        reg = requests.post(
            f"{BASE_URL}/register",
            json={
                "username": username,
                "password": password,
                "name": username,
                "phone": "0000000000",
                "email": f"{username}@example.com",
                "birth_year": "2000",
                "role": role,
            },
            timeout=5,
        )
        assert reg.status_code in (200, 201, 409)

        login = requests.post(
            f"{BASE_URL}/login",
            json={"username": username, "password": password},
            timeout=5,
        )
        assert login.status_code == 200, login.text
        token = login.json()["session_token"]
        return username, token

    return _make


@pytest.fixture()
def admin_token(make_user_and_login):
    _, token = make_user_and_login("ADMIN")
    return token


@pytest.fixture()
def user_token(make_user_and_login):
    username, token = make_user_and_login("USER")
    return username, token
