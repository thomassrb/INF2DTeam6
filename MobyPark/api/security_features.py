import threading
import time
import importlib
import hashlib

class security_features:
    def login_required(f):
        def wrapper(self, *args, **kwargs):
            session_user = self._get_user_from_session()
            if not session_user:
                self._send_response(401, "application/json", {"error": "Authentication required"})
                return
            return f(self, session_user, *args, **kwargs)
        return wrapper

    def roles_required(roles):
        def decorator(f):
            def wrapper(self, *args, **kwargs):
                session_user = self._get_user_from_session()
                if not session_user:
                    self._send_response(401, "application/json", {"error": "Authentication required"})
                    return
                if session_user.get("role") not in roles:
                    self._send_response(403, "application/json", {"error": "Access denied"})
                    return
                return f(self, session_user, *args, **kwargs)
            return wrapper
        return decorator
    
    
    def _hash_password(self, password: str) -> str:
        try:
            bcrypt = importlib.import_module("bcrypt")
        except ImportError as exc:
            raise RuntimeError("bcrypt is not installed. Please install with: pip install bcrypt") from exc
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def _looks_like_bcrypt(self, hashed: str) -> bool:
        return isinstance(hashed, str) and hashed.startswith(('$2b$', '$2a$', '$2y$'))
    
    def _verify_password(self, plain_password: str, stored_hash: str) -> bool:
        if self._looks_like_bcrypt(stored_hash):
            try:
                bcrypt = importlib.import_module("bcrypt")
            except ImportError as exc:
                raise RuntimeError("bcrypt is not installed. Please install with: pip install bcrypt") from exc
            return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
        if self._looks_like_md5(stored_hash):
            return hashlib.md5(plain_password.encode()).hexdigest() == stored_hash
        return False
    def _looks_like_md5(self, hashed: str) -> bool:
        if not isinstance(hashed, str) or len(hashed) != 32:
            return False
        try:
            int(hashed, 16)
            return True
        except ValueError:
            return False
    def _strip_unsafe_string(self, value: str, max_length: int) -> str:
        cleaned = re.sub(r"[\x00-\x1F\x7F]", "", value)
        cleaned = cleaned.strip()
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length]
        return cleaned
    

class session_timer:    
    def __init__(self, timeout=1800):
        self.timeout = timeout
        self.last_activity = time.time()
        self.session_expiry_maintenance()

        def update_activity(self):
            self.last_activity = time.time()

        def session_expiry_maintenance(self):
                timer = threading.Timer(600, self.session_expiry_maintenance)
                timer.daemon = True
                timer.start()
                if time.time() - self.last_activity > self.timeout:
                    self._handle_logout()