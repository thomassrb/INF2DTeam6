# MobyPark/api/session_manager.py

from typing import Dict, Optional
from datetime import datetime
from .Models.User import User  # adjust import if your path is different

# Simple in-memory session store: token -> User
_SESSIONS: Dict[str, User] = {}


def add_session(token: str, user: User) -> None:
    """
    Store a user for a given session token.
    No file IO, no custom store, just a simple dict.
    """
    _SESSIONS[token] = user


def get_session(token: str) -> Optional[User]:
    """
    Return the User for this session token, or None if not found.
    """
    return _SESSIONS.get(token)


def remove_session(token: str) -> Optional[User]:
    """
    Remove a session and return the User that was stored, if any.
    """
    return _SESSIONS.pop(token, None)
