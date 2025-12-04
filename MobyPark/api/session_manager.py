import os
import json
import threading
from typing import Optional, Dict, Any
from MobyPark.api.Models.User import User
from datetime import datetime


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))    # Absolute pad van de directory waar dit script staat
_DATA_DIR = os.environ.get('MOBYPARK_DATA_DIR') or os.path.join(_SCRIPT_DIR, '..', '..', 'MobyPark-api-data', 'pdata')
_SESSIONS_FILE = os.path.join(_DATA_DIR, 'sessions.json')

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

    def add(self, token: str, user: Dict[str, Any]) -> None:
        # Voegt een user toe aan de session en slaat changes op
        # user is al een dict – NIET nog een keer __dict__ aanroepen
        with _LOCK:
            self._sessions[token] = user
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


def remove_session(token: str) -> Optional[Dict[str, Any]]:
    # Dit delete een session
    return _STORE.remove(token)


def get_session(token: str) -> Optional[Dict[str, Any]]:
    # Haalt session op op basis van token
    return _STORE.get(token)


def update_session_user(token: str, user_data: Dict[str, Any]) -> None:
    # Werkt de gegevens van een user bij in bestaande session
    _STORE.update_user(token, user_data)



def add_session(token: str, user: User) -> None:
    # Maak een kopie van de user-data als dict
    user_data: Dict[str, Any] = dict(user.__dict__)

    # Wachtwoord niet in de session opslaan
    user_data.pop("password", None)

    # created_at moet JSON-serialiseerbaar zijn
    created_at = user_data.get("created_at")
    if isinstance(created_at, datetime):
        # Zet datetime om naar ISO-string
        user_data["created_at"] = created_at.isoformat()
    elif created_at is None:
        # Als er helemaal geen created_at is, vul een default in
        user_data["created_at"] = datetime.now().isoformat()
    else:
        # Als het al een string is, laten we het zo
        user_data["created_at"] = str(created_at)

    # Sla de session op in de onderliggende store
    _STORE.add(token, user_data)
