import uuid
import pytest
import requests
from datetime import datetime, timedelta

# Test data
TEST_VEHICLE = {
    "licenseplate": "TEST123",
    "name": "Test Car"
}

def test_vehicle_lifecycle(server_process, make_user_and_login):
    # Create a test user and get auth token
    user, token = make_user_and_login("USER")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Create a new vehicle
    create_response = requests.post(
        f"http://localhost:8000/vehicles",
        json=TEST_VEHICLE,
        headers=headers
    )
    assert create_response.status_code == 201
    vehicle = create_response.json()
    assert vehicle["licenseplate"] == TEST_VEHICLE["licenseplate"]
    assert vehicle["name"] == TEST_VEHICLE["name"]
    
    # Test 2: Get vehicle details
    get_response = requests.get(
        f"http://localhost:8000/vehicles/{vehicle['id']}",
        headers=headers
    )
    assert get_response.status_code == 200
    assert get_response.json() == vehicle
    
    # Test 3: List all vehicles
    list_response = requests.get(
        "http://localhost:8000/vehicles",
        headers=headers
    )
    assert list_response.status_code == 200
    vehicles = list_response.json()
    assert any(v["id"] == vehicle["id"] for v in vehicles)
    
    # Test 4: Update vehicle
    updated_name = "Updated Test Car"
    update_response = requests.patch(
        f"http://localhost:8000/vehicles/{vehicle['id']}",
        json={"name": updated_name},
        headers=headers
    )
    assert update_response.status_code == 200
    assert update_response.json()["name"] == updated_name
    
    # Test 5: Get vehicle history (should be empty for new vehicle)
    history_response = requests.get(
        f"http://localhost:8000/vehicles/{vehicle['licenseplate']}/history",
        headers=headers
    )
    assert history_response.status_code == 200
    assert history_response.json() == []
    
    # Test 6: Delete vehicle
    delete_response = requests.delete(
        f"http://localhost:8000/vehicles/{vehicle['id']}",
        headers=headers
    )
    assert delete_response.status_code == 200
    
    # Verify vehicle is deleted
    get_deleted = requests.get(
        f"http://localhost:8000/vehicles/{vehicle['id']}",
        headers=headers
    )
    assert get_deleted.status_code == 404

def test_vehicle_unauthorized_access(server_process, make_user_and_login):
    # Create two users
    user1, token1 = make_user_and_login("USER")
    user2, token2 = make_user_and_login("USER")
    
    # User1 creates a vehicle
    headers1 = {"Authorization": f"Bearer {token1}"}
    create_response = requests.post(
        "http://localhost:8000/vehicles",
        json=TEST_VEHICLE,
        headers=headers1
    )
    vehicle = create_response.json()
    
    # User2 tries to access user1's vehicle
    headers2 = {"Authorization": f"Bearer {token2}"}
    get_response = requests.get(
        f"http://localhost:8000/vehicles/{vehicle['id']}",
        headers=headers2
    )
    assert get_response.status_code == 403

def test_vehicle_admin_access(server_process, make_user_and_login):
    # Create admin and regular user
    admin, admin_token = make_user_and_login("ADMIN")
    user, user_token = make_user_and_login("USER")
    
    # User creates a vehicle
    user_headers = {"Authorization": f"Bearer {user_token}"}
    create_response = requests.post(
        "http://localhost:8000/vehicles",
        json=TEST_VEHICLE,
        headers=user_headers
    )
    vehicle = create_response.json()
    
    # Admin can access user's vehicle
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    get_response = requests.get(
        f"http://localhost:8000/vehicles/{vehicle['id']}?username={user['username']}",
        headers=admin_headers
    )
    assert get_response.status_code == 200
    assert get_response.json()["id"] == vehicle["id"]

def test_vehicle_validation(server_process, make_user_and_login):
    # Create test user
    user, token = make_user_and_login("USER")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test missing required fields
    response = requests.post(
        "http://localhost:8000/vehicles",
        json={"name": "Invalid Vehicle"},  # Missing licenseplate
        headers=headers
    )
    assert response.status_code == 422  # Validation error
    
    # Test invalid license plate format
    response = requests.post(
        "http://localhost:8000/vehicles",
        json={"licenseplate": "INVALID!@#", "name": "Invalid"},
        headers=headers
    )
    assert response.status_code == 422  # Validation error
