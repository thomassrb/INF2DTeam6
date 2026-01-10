# MobyPark/api/session_manager.py

from typing import Dict, Optional
from datetime import datetime, timedelta
import os
from .Models.User import User  # adjust import if your path is different

# Simple in-memory session store: token -> (user, expiry_time)
_SESSIONS: Dict[str, tuple[User, datetime]] = {}
# Session timeout (1 hour)
SESSION_TIMEOUT = timedelta(hours=1)

def _cleanup_expired_sessions():
    """Remove expired sessions from the session store."""
    current_time = datetime.now()
    expired = [token for token, (_, expiry) in _SESSIONS.items() if expiry < current_time]
    for token in expired:
        _SESSIONS.pop(token, None)
        print(f"DEBUG: Expired session cleaned up: {token}")

def add_session(token: str, user: User) -> None:
    """
    Store a user for a given session token with an expiry time.
    """
    expiry_time = datetime.now() + SESSION_TIMEOUT
    _SESSIONS[token] = (user, expiry_time)
    print(f"DEBUG: Added session for user {user.username} with token {token[:8]}...")
    _cleanup_expired_sessions()

def get_session(token: str) -> Optional[User]:
    """
    Return the User for this session token if it exists and is not expired.
    Returns None if the session is invalid or expired.
    """
    if not token or not isinstance(token, str):
        print("DEBUG: Invalid token format")
        return None
        
    session_data = _SESSIONS.get(token)
    if not session_data:
        print(f"DEBUG: No session found for token: {token[:8]}...")
        return None
        
    user, expiry_time = session_data
    
    if datetime.now() > expiry_time:
        print(f"DEBUG: Session expired for token: {token[:8]}...")
        _SESSIONS.pop(token, None)
        return None
        
    # Update the expiry time on access
    _SESSIONS[token] = (user, datetime.now() + SESSION_TIMEOUT)
    print(f"DEBUG: Retrieved session for user {user.username} with token {token[:8]}...")
    return user

def remove_session(token: str) -> Optional[User]:
    """
    Remove a session and return the User that was stored, if any.
    """
    if not token:
        return None
        
    session_data = _SESSIONS.pop(token, None)
    if session_data:
        user, _ = session_data
        print(f"DEBUG: Removed session for user {user.username} with token {token[:8]}...")
        return user
    return None

def list_sessions() -> Dict[str, dict]:
    """
    Return a dictionary of active sessions for debugging purposes.
    """
    _cleanup_expired_sessions()
    return {
        token[:8] + '...': {
            'username': user.username,
            'role': user.role,
            'expires_in': (expiry - datetime.now()).total_seconds() // 60
        }
        for token, (user, expiry) in _SESSIONS.items()
    }
