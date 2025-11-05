import bcrypt
import hashlib
import time
import os
import re
import json
from datetime import datetime

class PasswordManager:
    def _hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def _looks_like_bcrypt(self, hashed: str) -> bool:
        return isinstance(hashed, str) and hashed.startswith(('$2b$', '$2a$', '$2y$'))

    def _looks_like_md5(self, hashed: str) -> bool:
        if not isinstance(hashed, str) or len(hashed) != 32:
            return False
        try:
            int(hashed, 16)
            return True
        except ValueError:
            return False

    def _verify_password(self, plain_password: str, stored_hash: str) -> bool:
        if self._looks_like_bcrypt(stored_hash):
            return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
        if self._looks_like_md5(stored_hash):
            return hashlib.md5(plain_password.encode()).hexdigest() == stored_hash
        return False

class RateLimiter:
    def __init__(self):
        self._RL_WINDOW_SEC = int(os.environ.get('MOBYPARK_RL_WINDOW_SEC', '60'))
        self._RL_IP_MAX = int(os.environ.get('MOBYPARK_RL_IP_MAX', '20'))
        self._RL_USER_MAX = int(os.environ.get('MOBYPARK_RL_USER_MAX', '10'))
        self._LOCKOUT_AFTER = int(os.environ.get('MOBYPARK_LOCKOUT_AFTER', '5'))
        self._LOCKOUT_SECONDS = int(os.environ.get('MOBYPARK_LOCKOUT_SECONDS', '300'))

        self._ip_attempts: dict = {}
        self._user_attempts: dict = {}
        self._ip_lockouts: dict = {}
        self._user_lockouts: dict = {}

    def _now(self):
        return int(time.time())

    def _prune_old(self, entries):
        cutoff = self._now() - self._RL_WINDOW_SEC
        return [t for t in entries if t >= cutoff]

    def check_rate_limits_and_lockouts(self, ip_address, username):
        now = self._now()

        ip_until = self._ip_lockouts.get(ip_address)
        if isinstance(ip_until, int) and ip_until > now:
            return True, max(1, ip_until - now), {"error": "Too many attempts from IP. Try later."}
        user_until = self._user_lockouts.get(username)
        if isinstance(user_until, int) and user_until > now:
            return True, max(1, user_until - now), {"error": "Account temporarily locked. Try later."}

        ip_entries = self._prune_old(self._ip_attempts.get(ip_address, []))
        self._ip_attempts[ip_address] = ip_entries
        if len(ip_entries) >= self._RL_IP_MAX:
            retry_after = max(1, (ip_entries[0] + self._RL_WINDOW_SEC) - now)
            return True, retry_after, {"error": "Rate limit exceeded for IP."}

        user_entries = self._prune_old(self._user_attempts.get(username, []))
        self._user_attempts[username] = user_entries
        if len(user_entries) >= self._RL_USER_MAX:
            retry_after = max(1, (user_entries[0] + self._RL_WINDOW_SEC) - now)
            return True, retry_after, {"error": "Rate limit exceeded for user."}

        return False, 0, None

    def record_login_attempt(self, ip_address, username, success):
        now = self._now()
        if success:
            self._user_attempts.pop(username, None)
            self._ip_attempts[ip_address] = self._prune_old(self._ip_attempts.get(ip_address, []))
            return
        ip_entries = self._prune_old(self._ip_attempts.get(ip_address, []))
        ip_entries.append(now)
        self._ip_attempts[ip_address] = ip_entries

        user_entries = self._prune_old(self._user_attempts.get(username, []))
        user_entries.append(now)
        self._user_attempts[username] = user_entries

        if self._LOCKOUT_AFTER > 0 and len(user_entries) >= self._LOCKOUT_AFTER:
            self._user_lockouts[username] = now + self._LOCKOUT_SECONDS
        if self._LOCKOUT_AFTER > 0 and len(ip_entries) >= self._LOCKOUT_AFTER:
            self._ip_lockouts[ip_address] = now + self._LOCKOUT_SECONDS

class HTTPSecurity:
    def __init__(self):
        self._FORCE_HTTPS = False
        self._TRUST_PROXY = os.environ.get('MOBYPARK_TRUST_PROXY', '1') != '0'
        self._CORS_ORIGINS = [o.strip() for o in os.environ.get('MOBYPARK_CORS_ORIGINS', '').split(',') if o.strip()]
        self._CORS_ALLOW_HEADERS = os.environ.get('MOBYPARK_CORS_ALLOW_HEADERS', 'Authorization, Content-Type')
        self._CORS_ALLOW_METHODS = os.environ.get('MOBYPARK_CORS_ALLOW_METHODS', 'GET, POST, PUT, DELETE, OPTIONS')

    def _is_origin_allowed(self, origin):
        if not origin:
            return False
        if not self._CORS_ORIGINS:
            return False
        return origin in self._CORS_ORIGINS

    def _is_secure(self, headers):
        if self._TRUST_PROXY:
            xfproto = headers.get('X-Forwarded-Proto')
            if xfproto and 'https' in xfproto.split(',')[0].strip().lower():
                return True
            forwarded = headers.get('Forwarded')
            if forwarded and 'proto=https' in forwarded.lower():
                return True
        return False

    def enforce_https(self, handler, headers, path):
        if self._FORCE_HTTPS and not self._is_secure(headers):
            host = headers.get('Host', 'localhost')
            location = f"https://{host}{path}"
            handler.send_response(308)
            handler.send_header('Location', location)
            handler.send_header('Content-Length', '0')
            self._apply_security_headers(handler, headers)
            handler.end_headers()
            return True
        return False

    def _apply_security_headers(self, handler, headers):
        handler.send_header('X-Content-Type-Options', 'nosniff')
        handler.send_header('X-Frame-Options', 'DENY')
        handler.send_header('Referrer-Policy', 'no-referrer')
        handler.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        handler.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        handler.send_header('Cross-Origin-Resource-Policy', 'same-site')
        csp = (
            "default-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "style-src 'self'; "
            "script-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'"
        )
        handler.send_header('Content-Security-Policy', csp)

        origin = headers.get('Origin')
        if self._is_origin_allowed(origin):
            handler.send_header('Access-Control-Allow-Origin', origin)
            handler.send_header('Vary', 'Origin')
            handler.send_header('Access-Control-Allow-Credentials', 'true')

class DataValidator:
    def __init__(self):
        self._FORMAT_REGEX = {
            'username': re.compile(r'^[A-Za-z0-9_.-]{3,32}$'),
            'role': re.compile(r'^(USER|ADMIN)$'),
            'licenseplate': re.compile(r'^[A-Z0-9_-]{2,20}$'),
            'transaction': re.compile(r'^[A-Za-z0-9:_-]{1,128}$'),
        }

        self._FIELD_MAXLEN = {
            'username': 32,
            'name': 100,
            'role': 5,
            'licenseplate': 16,
            'transaction': 128,
            'password': 256,
        }

    def _strip_unsafe_string(self, value: str, max_length: int) -> str:
        cleaned = re.sub(r"[\x00-\x1F\x7F]", "", value)
        cleaned = cleaned.strip()
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length]
        return cleaned

    def validate_data(self, data, required_fields=None, optional_fields=None, allow_unknown=False):
        # Even een one liner van gemaakt ipv twee liners :)
        required_fields = required_fields or {}
        optional_fields = optional_fields or {}

        for field, expected_type in required_fields.items():
            if field not in data:
                return False, {"error": "Required field missing", "field": field}
            if not isinstance(data[field], expected_type):
                return False, {"error": f"Invalid type for field {field}", "expected_type": str(expected_type), "received_type": str(type(data[field]))}

        for field, expected_type in optional_fields.items():
            if field in data and not isinstance(data[field], expected_type):
                return False, {"error": f"Invalid type for field {field}", "expected_type": str(expected_type), "received_type": str(type(data[field]))}

        if not allow_unknown:
            allowed = set(required_fields.keys()) | set(optional_fields.keys())
            unknown = [k for k in data.keys() if k not in allowed]
            if unknown:
                return False, {"error": "Unknown fields present", "fields": unknown}

        for key, val in list(data.items()):
            if isinstance(val, str):
                maxlen = self._FIELD_MAXLEN.get(key, 256)
                data[key] = self._strip_unsafe_string(val, maxlen)

        for fname, regex in self._FORMAT_REGEX.items():
            if fname in data and isinstance(data[fname], str):
                if fname == 'licenseplate':
                    candidate = data[fname].upper()
                else:
                    candidate = data[fname]
                if not regex.match(candidate):
                    return False, {"error": "Invalid format", "field": fname}

        for df in ('startdate', 'enddate'):
            if df in data and isinstance(data[df], str):
                if not self._validate_date_string(data[df]):
                    return False, {"error": "Invalid date format", "field": df}

        return True, None

    def _validate_date_string(self, date_string: str) -> bool:
        formats = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%m-%Y"]
        for fmt in formats:
            try:
                datetime.strptime(date_string, fmt)
                return True
            except ValueError:
                pass
        return False

class AuditLogger:
    def audit(self, session_user, action, *, target=None, extra=None, status="SUCCESS"):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            data_dir = os.path.join(script_dir, '..', '..', 'data')
            os.makedirs(data_dir, exist_ok=True)
            log_path = os.path.join(data_dir, 'audit.log')
            entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "user": session_user.get("username") if session_user else None,
                "role": session_user.get("role") if session_user else None,
                "action": action,
                "target": target,
                "status": status,
                "extra": extra,
            }
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass
