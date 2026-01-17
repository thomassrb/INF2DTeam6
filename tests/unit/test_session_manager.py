import uuid

from MobyPark.api import session_manager


def test_add_get_remove_session_roundtrip():
    token = str(uuid.uuid4())
    user = object()

    session_manager.add_session(token, user)
    assert session_manager.get_session(token) is user

    removed = session_manager.remove_session(token)
    assert removed is user
    assert session_manager.get_session(token) is None


def test_remove_unknown_session_returns_none():
    token = str(uuid.uuid4())
    assert session_manager.get_session(token) is None
    assert session_manager.remove_session(token) is None
