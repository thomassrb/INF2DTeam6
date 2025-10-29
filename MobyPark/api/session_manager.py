import os
import json
import threading
import importlib
import asyncio
from typing import Optional, Dict, Any

_redis_mod = None

def _load_redis_module():
    global _redis_mod
    if _redis_mod is None:
        try:
            _redis_mod = importlib.import_module('redis')
        except ImportError:
            _redis_mod = None
    return _redis_mod

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_SCRIPT_DIR, '..', '..', 'data')
_SESSIONS_FILE = os.path.join(_DATA_DIR, 'sessions.json')

_LOCK = threading.Lock()


class _BaseSessionStore:
    async def add(self, token: str, user: Dict[str, Any]) -> None:
        raise NotImplementedError

    async def remove(self, token: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    async def get(self, token: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    async def update_user(self, token: str, user_data: Dict[str, Any]) -> None:
        raise NotImplementedError


class _FileSessionStore(_BaseSessionStore):
    def __init__(self):
        os.makedirs(_DATA_DIR, exist_ok=True)
        self._sessions: Dict[str, Dict[str, Any]] = self._load_initial_sessions()

    def _load_initial_sessions(self) -> Dict[str, Any]:
        try:
            with open(_SESSIONS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                else:
                    return {}
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {_SESSIONS_FILE}. Returning empty dictionary.")
            return {}

    def _flush(self) -> None:
        with open(_SESSIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self._sessions, f, ensure_ascii=False, indent=2)

    async def add(self, token: str, user: Dict[str, Any]) -> None:
        with _LOCK:
            self._sessions[token] = user
        await asyncio.to_thread(self._flush)

    async def remove(self, token: str) -> Optional[Dict[str, Any]]:
        with _LOCK:
            user = self._sessions.pop(token, None)
        await asyncio.to_thread(self._flush)
        return user

    async def get(self, token: str) -> Optional[Dict[str, Any]]:
        with _LOCK:
            return self._sessions.get(token)

    async def update_user(self, token: str, user_data: Dict[str, Any]) -> None:
        with _LOCK:
            if token in self._sessions and isinstance(self._sessions[token], dict):
                self._sessions[token].update(user_data)
        await asyncio.to_thread(self._flush)


class _RedisSessionStore(_BaseSessionStore):
    def __init__(self, url: str, ttl_seconds: Optional[int] = None):
        mod = _load_redis_module()
        if mod is None:
            raise RuntimeError("redis package not available")
        self._client = mod.from_url(url)
        self._ttl = ttl_seconds
        self._prefix = 'session:'

    def _key(self, token: str) -> str:
        return f"{self._prefix}{token}"

    async def add(self, token: str, user: Dict[str, Any]) -> None:
        payload = json.dumps(user, ensure_ascii=False)
        if self._ttl and self._ttl > 0:
            await self._client.set(self._key(token), payload, ex=self._ttl)
        else:
            await self._client.set(self._key(token), payload)

    async def remove(self, token: str) -> Optional[Dict[str, Any]]:
        key = self._key(token)
        data = await self._client.get(key)
        await self._client.delete(key)
        if not data:
            return None
        try:
            return json.loads(data)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    async def get(self, token: str) -> Optional[Dict[str, Any]]:
        data = await self._client.get(self._key(token))
        if not data:
            return None
        try:
            return json.loads(data)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    async def update_user(self, token: str, user_data: Dict[str, Any]) -> None:
        key = self._key(token)
        data = await self._client.get(key)
        if not data:
            return
        try:
            existing = json.loads(data)
            if isinstance(existing, dict):
                existing.update(user_data)
                payload = json.dumps(existing, ensure_ascii=False)
                if self._ttl and self._ttl > 0:
                    await self._client.set(key, payload, ex=self._ttl)
                else:
                    await self._client.set(key, payload)
        except (ValueError, TypeError, json.JSONDecodeError):
            return


def _create_store() -> _BaseSessionStore:
    redis_url = os.environ.get('MOBYPARK_REDIS_URL') or os.environ.get('REDIS_URL')
    ttl = os.environ.get('MOBYPARK_SESSION_TTL')
    ttl_int = int(ttl) if ttl and ttl.isdigit() else None
    if redis_url and _load_redis_module() is not None:
        try:
            return _RedisSessionStore(redis_url, ttl_int)
        except (RuntimeError, OSError, ValueError):
            pass
    return _FileSessionStore()


_STORE: _BaseSessionStore = _create_store()


async def add_session(token: str, user: Dict[str, Any]) -> None:
    await _STORE.add(token, user)


async def remove_session(token: str) -> Optional[Dict[str, Any]]:
    return await _STORE.remove(token)


async def get_session(token: str) -> Optional[Dict[str, Any]]:
    return await _STORE.get(token)


async def update_session_user(token: str, user_data: Dict[str, Any]) -> None:
    await _STORE.update_user(token, user_data)