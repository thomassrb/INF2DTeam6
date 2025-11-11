# Kleine aantek; deze file komen alle authenticatie gerelateerde code snippets van de server.py

import hashlib
import uuid
import bcrypt
from datetime import datetime
from storage_utils import load_json, save_user_data
import session_manager
import re

def login_required(func):
    def wrapper(self, *args, **kwargs):
        session_user = get_user_from_session(self)
        if not session_user:
            self.send_json_response(401, "application/json", {"error": "Unauthorized"})
            return
        return func(self, session_user, *args, **kwargs)
    return wrapper

def roles_required(roles):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            session_user = get_user_from_session(self)
            if not session_user:
                self.send_json_response(401, "application/json", {"error": "Unauthorized"})
                return
            if session_user.get("role") not in roles:
                self.send_json_response(403, "application/json", {"error": "Access denied"})
                return
            return func(self, session_user, *args, **kwargs)
        return wrapper
    return decorator


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
    session_data = session_manager.get_session(token)
    if not session_data:
        print(f"DEBUG: No session found for token: {token}")
    else:
        print(f"DEBUG: Session found for token {token}, user: {session_data.get('username')}")
    return session_data if session_data else None

def handle_update_profile(handler, session_user):
    data = handler.get_request_data()
    
    valid, error = handler.data_validator.validate_data(data,
        optional_fields={'name': str, 'password': str}
    )
    if not valid:
        handler.send_json_response(400, "application/json", error)
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
    handler.send_json_response(200, "application/json", {"message": "User updated successfully"})


class PasswordManager:
    def hash_password(self, password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()