import os
import subprocess
import sys
import time
import signal
from pathlib import Path

import pytest
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
APP_MODULE = "MobyPark.api.app:app"
TEST_DATA_DIR = Path(__file__).resolve().parents[2] / "test_data"
TEST_DB_PATH = TEST_DATA_DIR / "test.db"

TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

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
    env = os.environ.copy()
    env["MOBYPARK_DB_DIR"] = str(TEST_DATA_DIR)
    
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload",
            APP_MODULE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    
    try:
        wait_for_server(f"{BASE_URL}/")
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        
        if TEST_DB_PATH.exists():
            os.remove(TEST_DB_PATH)
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
