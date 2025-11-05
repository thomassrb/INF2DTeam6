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
