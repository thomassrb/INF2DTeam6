import os
import json
import threading
from typing import Optional, Dict, Any
from Models.User import User

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))    # Geeft het absolute pad van de directory terug  waar het scriptbestand staat
_DATA_DIR = os.path.join(_SCRIPT_DIR, '..', '..', 'data')   # Bepaalt het pad naar de data-directory
_SESSIONS_FILE = os.path.join(_DATA_DIR, 'sessions.json')   # Zorgt ervoor het pad naar de sessions.json

_LOCK = threading.Lock()                                    # Maakt een lock voor thread sync.


class _BaseSessionStore:
    # Add een user aan de session met de given token
    def add(self, token: str, user: Dict[str, Any]) -> None:
        raise NotImplementedError

    # Verwijderd de session en geeft de token terug aan de user
    def remove(self, token: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    # Geeft de gebruiker terug aan de juiste token, en none als token niet bestaat
    def get(self, token: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    # Werkt de gegevens van de user bij voor de sessie met de token
    def update_user(self, token: str, user_data: Dict[str, Any]) -> None:
        raise NotImplementedError


class _FileSessionStore(_BaseSessionStore):
    # Maakt de data-directory aan indien deze nog niet bestaat en probeert bestaande sessies te laden
    # uit de sessions.json. Als het bestand ontbreekt of niet geldig is  wordt er een empty sessie-dict gebruikt.
    def __init__(self):
        os.makedirs(_DATA_DIR, exist_ok=True)
        try:
            with open(_SESSIONS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._sessions: Dict[str, Dict[str, Any]] = data
                else:
                    self._sessions = {}
        except FileNotFoundError:
            self._sessions = {}
        except json.JSONDecodeError:
            self._sessions = {}

    def _flush(self) -> None:
        # Slaat de huidige sessions op in session.json
        with open(_SESSIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self._sessions, f, ensure_ascii=False, indent=2)

    def add(self, token: str, user: User) -> None:
        # Voegt een user toe aan de session en slaat changes op
        with _LOCK:
            self._sessions[token] = user.__dict__
            self._flush()

    def remove(self, token: str) -> Optional[User]:
        # Delete een session en returned de bijbehorende user
        with _LOCK:
            user = self._sessions.pop(token, None)
            self._flush()
            return User(**user)

    def get(self, token: str) -> Optional[User]:
        # Haalt de user op die bij de given token hoort, anders none als token invalid is
        with _LOCK:
            user_dict = self._sessions.get(token)
            return User(**user_dict)

    def update_user(self, token: str, user_data: Dict[str, Any]) -> None:
        # Update de gegevens van de gebruiker en slaat de wijzegingen op
        with _LOCK:
            if token in self._sessions and isinstance(self._sessions[token], dict):
                self._sessions[token].update(user_data)
                self._flush()


def _create_store() -> _BaseSessionStore:
    # Dit maakt en initialiseert de session opslag
    return _FileSessionStore()

_STORE: _BaseSessionStore = _create_store()


def add_session(token: str, user: Dict[str, Any]) -> None:
    # Dit voegt een session toe
    _STORE.add(token, user)


def remove_session(token: str) -> Optional[Dict[str, Any]]:
    # Dit delete een session
    return _STORE.remove(token)


def get_session(token: str) -> Optional[Dict[str, Any]]:
    # Haalt session op op basis van token
    return _STORE.get(token)


def update_session_user(token: str, user_data: Dict[str, Any]) -> None:
    # Werkt de gegevens van een user bij in bestaande session
    _STORE.update_user(token, user_data)