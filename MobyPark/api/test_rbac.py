
import requests
import json

BASE_URL = "http://localhost:8000"

def print_response(title, response):
    print(f"\n--- {title} ---")
    print(f"Status Code: {response.status_code}")
    try:
        print("Response Body:", json.dumps(response.json(), indent=2))
    except requests.exceptions.JSONDecodeError:
        print("Response Body (raw):", response.text)
    if 'Authorization' in response.headers:
        print("Authorization Header (from response):", response.headers['Authorization'])

def run_tests():
    print("\n### Test 1: Accessing protected endpoint without authentication")
    try:
        response = requests.get(f"{BASE_URL}/profile", allow_redirects=True, verify=False)
        print_response("GET /profile (no auth)", response)
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        print("Test 1 Passed: Received 401 Unauthorized as expected.")
    except Exception as e:
        print(f"Test 1 Failed: {e}")

    print("\n### Test 2: Logging in as regular user")
    user_token = None
    try:
        login_data = {"username": "testuser", "password": "password123"}
        response = requests.post(f"{BASE_URL}/login", json=login_data, allow_redirects=True, verify=False)
        print_response("POST /login (testuser)", response)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        if "Authorization" in response.headers:
            user_token = response.headers["Authorization"].split(" ")[1]
            print(f"Extracted User Token: {user_token}")
        else:
            print("Login failed: No Authorization header in response.")
        assert user_token is not None, "Failed to get user token"
        print("Test 2 Passed: Logged in successfully and got user token.")
    except Exception as e:
        print(f"Test 2 Failed: {e}")

    # Test 3: Accessing /profile with a valid user token (Expected: 200 OK)
    print("\n### Test 3: Accessing /profile with valid user token")
    if user_token:
        headers = {"Authorization": f"Bearer {user_token}"}
        try:
            response = requests.get(f"{BASE_URL}/profile", headers=headers, allow_redirects=True, verify=False)
            print_response("GET /profile (with user auth)", response)
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            print("Test 3 Passed: Accessed /profile successfully with user token.")
        except Exception as e:
            print(f"Test 3 Failed: {e}")
    else:
        print("Test 3 Skipped: User token not available.")

    print("\n### Test 4: Accessing ADMIN endpoint with regular user token")
    if user_token:
        headers = {"Authorization": f"Bearer {user_token}"}
        try:
            response = requests.get(f"{BASE_URL}/billing/testuser", headers=headers, allow_redirects=True, verify=False)
            print_response("GET /billing/testuser (with user auth)", response)
            assert response.status_code == 403, f"Expected 403, got {response.status_code}"
            print("Test 4 Passed: Received 403 Forbidden as expected.")
        except Exception as e:
            print(f"Test 4 Failed: {e}")
    else:
        print("Test 4 Skipped: User token not available.")

    print("\n### Test 5: Logging in as admin user")
    admin_token = None
    try:
        login_data = {"username": "adminuser", "password": "password123"}
        response = requests.post(f"{BASE_URL}/login", json=login_data, allow_redirects=True, verify=False)
        print_response("POST /login (adminuser)", response)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        if "Authorization" in response.headers:
            admin_token = response.headers["Authorization"].split(" ")[1]
            print(f"Extracted Admin Token: {admin_token}")
        else:
            print("Login failed: No Authorization header in response.")
        assert admin_token is not None, "Failed to get admin token"
        print("Test 5 Passed: Logged in successfully and got admin token.")
    except Exception as e:
        print(f"Test 5 Failed: {e}")

    print("\n### Test 6: Accessing ADMIN endpoint with admin token")
    if admin_token:
        headers = {"Authorization": f"Bearer {admin_token}"}
        try:
            response = requests.get(f"{BASE_URL}/billing/testuser", headers=headers, allow_redirects=True, verify=False)
            print_response("GET /billing/testuser (with admin auth)", response)
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            print("Test 6 Passed: Accessed ADMIN endpoint successfully with admin token.")
        except Exception as e:
            print(f"Test 6 Failed: {e}")
    else:
        print("Test 6 Skipped: Admin token not available.")

if __name__ == "__main__":
    print("Starting RBAC tests...")
    run_tests()
    print("RBAC tests finished.")
