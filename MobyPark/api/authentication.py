# Kleine aantek; deze file komen alle authenticatie gerelateerde code snippets van de server.py

import hashlib
import uuid
import bcrypt
from datetime import datetime
from storage_utils import load_json, save_user_data
import re

def extract_bearer_token(headers):
    print(f"DEBUG: Headers in extract_bearer_token: {headers}")
    auth_header = headers.get('Authorization')
    if not auth_header:
        print("DEBUG: Authorization header not found.")
        return None
    parts = auth_header.split(' ', 1)
    if len(parts) != 2:
        print(f"DEBUG: Invalid Authorization header format: {auth_header}")
        return None
    scheme, token = parts
    if scheme.lower() != 'bearer' or not token:
        print(f"DEBUG: Invalid scheme or empty token: Scheme={scheme}, Token={token}")
        return None
    print(f"DEBUG: Extracted token: {token}")
    return token

def get_user_from_session(handler):
    print(f"DEBUG: Entering get_user_from_session for path: {handler.path}")
    token = extract_bearer_token(handler.headers)
    if not token:
        print("DEBUG: No token extracted from headers in get_user_from_session.")
        return None
    session_data = handler.session_manager.get_session(token)
    if not session_data:
        print(f"DEBUG: No session found for token: {token}")
    else:
        print(f"DEBUG: Session found for token {token}, user: {session_data.get('username')}")
    return session_data if session_data else None

def handle_register(handler):
    data = handler.get_request_data()

    required_fields = ['username', 'password', 'name', 'phone', 'email', 'birth_year']
    for field in required_fields:
        if field not in data or not isinstance(data[field], str) or not data[field].strip():
            handler.send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
            return

    username = data['username']
    password = data['password']
    name = data['name']
    phone_number = data['phone']
    email = data['email']
    birth_year = data['birth_year']


    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users = load_json('users.json')

    if any(user['username'] == username for user in users):
        handler.send_json_response(409, "application/json", {"error": "Username already taken"})
        return

    new_id = str(max(int(u.get("id", 0)) for u in users) + 1) if users else "1"
    new_user = {
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
    }
    users.append(new_user)
    save_user_data(users)
    handler.send_json_response(201, "application/json", {"message": "User created"})

def handle_login(handler):
    data = handler.get_request_data()

    required_fields = ['username', 'password']
    for field in required_fields:
        if field not in data or not isinstance(data[field], str) or not data[field].strip():
            handler.send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
            return

    username = data['username']
    password = data['password']

    users = load_json('users.json')
    user_to_authenticate = None
    print(f"DEBUG: Searching for user '{username}' in users list of type {type(users)}")
    for u in users:
        print(f"DEBUG: Checking user: {u.get('username')}")
        if u.get("username") == username:
            user_to_authenticate = u
            print(f"DEBUG: Found user {username}: {user_to_authenticate}")
            break

    # COMMENTS TOEVOEGEN VOOR ONDERSTAAND STATEMENT
    if user_to_authenticate:
        if user_to_authenticate.get("password", "").startswith("$2b$"):
            if bcrypt.checkpw(password.encode('utf-8'), user_to_authenticate["password"].encode('utf-8')):
                print(f"DEBUG: Bcrypt match for user {username}")
                token = str(uuid.uuid4())
                handler.session_manager.add_session(token, user_to_authenticate)
                handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                return
        else:
            hashed_password_input = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if hashed_password_input == user_to_authenticate.get("password", ""):
                print(f"DEBUG: SHA256 match for user {username}")
                token = str(uuid.uuid4())
                handler.session_manager.add_session(token, user_to_authenticate)
                handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                return

    print(f"DEBUG: Login failed for username: {username}. Provided password: {password}. Stored user: {user_to_authenticate}")
    handler.send_json_response(401, "application/json", {"error": "Invalid credentials"})

def handle_logout(handler):
    token = extract_bearer_token(handler.headers)
    if token and handler.session_manager.get_session(token):
        handler.session_manager.clear_sessions(token)
        handler.send_json_response(200, "application/json", {"message": "User logged out successfully"})
    else:
        handler.send_json_response(400, "application/json", {"error": "No active session or invalid token"})

def handle_update_profile(handler, session_user):
    data = handler.get_request_data()
    
    valid, error = handler.data_validator.validate_data(data,
        optional_fields={'name': str, 'password': str}
    )
    if not valid:
        handler.send_json_response(400, "application/json", error)
        return


    auth_header = handler.headers.get('Authorization')
    raw_token = extract_bearer_token(handler.headers)

    users = load_json('users.json')
    updated_user = None
    for i, user in enumerate(users):
        if user["username"] == session_user["username"]:
            for key, value in data.items():
                if key == "password":
                    users[i][key] = bcrypt.hashpw(value.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                elif key != "username":
                    users[i][key] = value
            updated_user = users[i]
            break
    save_user_data(users)

    if updated_user and raw_token:
        handler.session_manager.update_session_user(raw_token, updated_user)
    handler.audit_logger.audit(session_user, action="update_profile")
    handler.send_json_response(200, "application/json", {"message": "User updated successfully"})

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

    handler.send_json_response(200, "application/json", profile_data)

def handle_get_profile_by_id(handler, session_user):
    match = re.match(r"^/profile/([^/]+)$", handler.path)
    if not match:
        handler.send_json_response(400, "application/json", {"error": "Invalid URL format"})
        return
    
    target_user_id = match.group(1)
    
    users = load_json('users.json')
    target_user = next((u for u in users if u.get("id") == target_user_id), None)
    
    if not target_user:
        handler.send_json_response(404, "application/json", {"error": "User not found"})
        return
    
    is_admin = session_user["role"] == "ADMIN"
    
    if not is_admin and session_user.get("id") != target_user_id:
        handler.send_json_response(403, "application/json", {"error": "Access denied. You can only view your own profile."})
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
    
    handler.send_json_response(200, "application/json", profile_data)
