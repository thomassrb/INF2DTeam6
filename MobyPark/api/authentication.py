# Kleine aantek; deze file komen alle authenticatie gerelateerde code snippets van de server.py

import hashlib
import uuid
import bcrypt
import os
import re
from datetime import datetime

from MobyPark.api.storage_utils import load_json, save_user_data
from MobyPark.api import session_manager
# MobyPark/api/authentication.py

from typing import Optional
from fastapi import Header, HTTPException, status, Depends
from .session_manager import get_session
from .Models.User import User


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    """
    Extract 'token' from headers like: 'Bearer token'.
    This must keep the behaviour your unit tests expect.
    """
    DEBUG_LOGS = os.environ.get('DEBUG_LOGS') == '1'
    
    if not auth_header:
        if DEBUG_LOGS:
            print("DEBUG: No authorization header provided")
        return None

    try:
        parts = auth_header.split()
        if len(parts) != 2:
            if DEBUG_LOGS:
                print(f"DEBUG: Invalid authorization header format: {auth_header}")
            return None

        scheme, token = parts
        if scheme.lower() != "bearer":
            if DEBUG_LOGS:
                print(f"DEBUG: Invalid scheme in authorization header: {scheme}")
            return None

        if DEBUG_LOGS:
            print(f"DEBUG: Successfully extracted token: {token}")
        return token
    except Exception as e:
        if DEBUG_LOGS:
            print(f"DEBUG: Error extracting token: {str(e)}")
        return None


def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    """
    Resolve the current user from the Authorization header.
    Returns 401 for missing/invalid/expired tokens instead of 500.
    """
    DEBUG_LOGS = os.environ.get('DEBUG_LOGS') == '1'
    
    if DEBUG_LOGS:
        print(f"DEBUG: Authorization header: {authorization}")
    
    token = extract_bearer_token(authorization)
    if not token:
        if DEBUG_LOGS:
            print("DEBUG: No token extracted from authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization token",
        )

    if DEBUG_LOGS:
        print(f"DEBUG: Looking up session for token: {token}")
    
    user = get_session(token)
    if user is None:
        if DEBUG_LOGS:
            print(f"DEBUG: No session found for token: {token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    if DEBUG_LOGS:
        print(f"DEBUG: Found user: {user.username} with role: {user.role}")
    
    return user


def require_roles(*roles: str):
    """
    Dependency factory to guard endpoints by role.
    Example: Depends(require_roles("ADMIN"))
    - if user.role not in roles -> 403
    """
    def _dependency(user: User = Depends(get_current_user)) -> User:
        if roles and user.role not in roles:
            # This is what test_non_admin_cannot_view_other_users_billing_returns_403 expects.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return user

    return _dependency


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


# This function is kept for backward compatibility but should be deprecated
# in favor of the updated extract_bearer_token function above
def extract_bearer_token_from_headers(headers):
    DEBUG_LOGS = os.environ.get('DEBUG_LOGS') == '1'
    if DEBUG_LOGS:
        print(f"DEBUG: Headers in extract_bearer_token_from_headers: {headers}")
    
    if not headers:
        if DEBUG_LOGS:
            print("DEBUG: No headers provided to extract_bearer_token_from_headers")
        return None
    
    if not hasattr(headers, 'get'):
        if DEBUG_LOGS:
            print(f"DEBUG: Headers is not a dictionary-like object: {type(headers)}")
        return None
    
    auth_header = headers.get('Authorization')
    if not auth_header:
        if DEBUG_LOGS:
            print("DEBUG: Authorization header not found in headers")
        return None
    
    return extract_bearer_token(auth_header)

def get_user_from_session(handler):
    DEBUG_LOGS = os.environ.get('DEBUG_LOGS') == '1'
    if DEBUG_LOGS:
        print(f"DEBUG: Entering get_user_from_session for path: {handler.path}")
    
    if not hasattr(handler, 'headers'):
        if DEBUG_LOGS:
            print("DEBUG: Handler has no headers attribute")
        return None
    
    token = extract_bearer_token_from_headers(handler.headers)
    if not token:
        if DEBUG_LOGS:
            print("DEBUG: No token extracted from headers in get_user_from_session.")
        return None
    
    if DEBUG_LOGS:
        print(f"DEBUG: Looking up session for token: {token}")
    
    session_data = session_manager.get_session(token)
    if not session_data:
        if DEBUG_LOGS:
            print(f"DEBUG: No session found for token: {token}")
        return None
    
    if DEBUG_LOGS:
        print(f"DEBUG: Session found for token {token}, user: {session_data.get('username', 'unknown')}")
    
    return session_data

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