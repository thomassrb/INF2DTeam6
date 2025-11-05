# Kleine aantek; deze file komen alle authenticatie gerelateerde code snippets van de server.py

from datetime import datetime
import hashlib
import uuid
import bcrypt
import re
from storage_utils import load_json, save_user_data

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
