# Kleine aantek; deze file komen alle authenticatie gerelateerde code snippets van de server.py

import hashlib
import uuid
from datetime import datetime
from storage_utils import load_json, save_user_data
import re

def extract_bearer_token(headers):
    auth_header = headers.get('Authorization')
    if not auth_header:
        return None
    parts = auth_header.split(' ', 1)
    if len(parts) != 2:
        return None
    scheme, token = parts
    if scheme.lower() != 'bearer' or not token:
        return None
    return token

def get_user_from_session(handler):
    token = extract_bearer_token(handler.headers)
    if not token:
        return None
    session_data = handler.session_manager.get_session(token)
    return session_data if session_data else None

def handle_register(handler):
    data = handler.get_request_data()

    required_fields = ['username', 'password', 'name', 'phone', 'email', 'birth_year']
    for field in required_fields:
        if field not in data or not isinstance(data[field], str) or not data[field].strip():
            handler._send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
            return

    username = data['username']
    password = data['password']
    name = data['name']
    phone_number = data['phone']
    email = data['email']
    birth_year = data['birth_year']

    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    users = load_json('users.json')

    if any(user['username'] == username for user in users):
        handler._send_json_response(409, "application/json", {"error": "Username already taken"})
        return

    new_id = str(max(int(u.get("id", 0)) for u in users) + 1) if users else "1"
    users.append({
        'id': new_id,
        'username': username,
        'password': hashed_password,
        'name': name,
        'phone': phone_number,
        'email': email,
        'birth_year': birth_year,
        'role': data.get('role', 'USER'),
        'active': True,
        'created_at': datetime.now().strftime("%Y-%m-%d")
    })
    save_user_data(users)
    handler._send_json_response(201, "application/json", {"message": "User created"})

def handle_login(handler):
    data = handler.get_request_data()

    required_fields = ['username', 'password']
    for field in required_fields:
        if field not in data or not isinstance(data[field], str) or not data[field].strip():
            handler._send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
            return

    username = data['username']
    password = data['password']

    users = load_json('users.json')
    user_to_authenticate = None
    for u in users:
        if u.get("username") == username:
            user_to_authenticate = u
            break

    if user_to_authenticate:
        hashed_password_input = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if hashed_password_input == user_to_authenticate.get("password", ""):
            token = str(uuid.uuid4())
            handler.session_manager.add_session(token, user_to_authenticate)
            handler._send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
            return

    handler._send_json_response(401, "application/json", {"error": "Invalid credentials"})

def handle_logout(handler):
    token = extract_bearer_token(handler.headers)
    if token and handler.session_manager.get_session(token):
        handler.session_manager.clear_sessions(token)
        handler._send_json_response(200, "application/json", {"message": "User logged out successfully"})
    else:
        handler._send_json_response(400, "application/json", {"error": "No active session or invalid token"})

def handle_update_profile(handler, session_user):
    data = handler.get_request_data()
    
    valid, error = handler.data_validator.validate_data(data,
        optional_fields={'name': str, 'password': str}
    )
    if not valid:
        handler._send_json_response(400, "application/json", error)
        return

    data["username"] = session_user["username"]
    if data.get("password"):
        data["password"] = handler.password_manager.hash_password(data["password"])
    
    users = load_json('users.json')
    updated_user = None
    for i, user in enumerate(users):
        if user["username"] == session_user["username"]:
            if data.get("name"):
                users[i]["name"] = data["name"]
            if data.get("password"):
                users[i]["password"] = data["password"]
            updated_user = users[i]
            break
    save_user_data(users)
    token = handler.headers.get('Authorization')
    if updated_user:
        if updated_user and token:
            handler.session_manager.update_session_user(token, updated_user)
    handler.audit_logger.audit(session_user, action="update_profile")
    handler._send_json_response(200, "application/json", {"message": "User updated successfully"})

def handle_get_profile(handler, session_user):
    profile_data = {
    "username": session_user["username"],
    "role": session_user["role"],
    "name": session_user["name"],
    "email": session_user["email"],
    "phone": session_user["phone"],
    "birth_year": session_user.get("birth_year"),
    "created_at": session_user.get("created_at")
        }

    handler._send_json_response(200, "application/json", profile_data)

def handle_get_profile_by_id(handler, session_user):
    match = re.match(r"^/profile/([^/]+)$", handler.path)
    if not match:
        handler._send_json_response(400, "application/json", {"error": "Invalid URL format"})
        return
    
    target_user_id = match.group(1)
    
    users = load_json('users.json')
    target_user = next((u for u in users if u.get("id") == target_user_id), None)
    
    if not target_user:
        handler._send_json_response(404, "application/json", {"error": "User not found"})
        return
    
    is_admin = session_user["role"] == "ADMIN"
    
    if not is_admin and session_user.get("id") != target_user_id:
        handler._send_json_response(403, "application/json", {"error": "Access denied. You can only view your own profile."})
        return
    
    profile_data = {
        "id": target_user.get("id"),
        "username": target_user.get("username"),
        "role": target_user.get("role"),
        "name": target_user.get("name"),
        "email": target_user.get("email"),
        "phone": target_user.get("phone"),
        "birth_year": target_user.get("birth_year"),
        "created_at": target_user.get("created_at")
    }
    
    handler._send_json_response(200, "application/json", profile_data)
