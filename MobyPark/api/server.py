import json
import re
import os
import hashlib
import importlib
import uuid
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from storage_utils import load_json, save_data, save_user_data, load_parking_lot_data, save_parking_lot_data, save_reservation_data, load_reservation_data, load_payment_data, save_payment_data
from session_manager import add_session, get_session, update_session_user, remove_session
import session_calculator as sc


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


class RequestHandler(BaseHTTPRequestHandler):
    _MAX_JSON_BYTES = 64 * 1024

    _FORCE_HTTPS = False
    # _FORCE_HTTPS = os.environ.get('MOBYPARK_FORCE_HTTPS', '1') != '0'
    _TRUST_PROXY = os.environ.get('MOBYPARK_TRUST_PROXY', '1') != '0'
    _CORS_ORIGINS = [o.strip() for o in os.environ.get('MOBYPARK_CORS_ORIGINS', '').split(',') if o.strip()]
    _CORS_ALLOW_HEADERS = os.environ.get('MOBYPARK_CORS_ALLOW_HEADERS', 'Authorization, Content-Type')
    _CORS_ALLOW_METHODS = os.environ.get('MOBYPARK_CORS_ALLOW_METHODS', 'GET, POST, PUT, DELETE, OPTIONS')

    _RL_WINDOW_SEC = int(os.environ.get('MOBYPARK_RL_WINDOW_SEC', '60'))
    _RL_IP_MAX = int(os.environ.get('MOBYPARK_RL_IP_MAX', '20'))
    _RL_USER_MAX = int(os.environ.get('MOBYPARK_RL_USER_MAX', '10'))
    _LOCKOUT_AFTER = int(os.environ.get('MOBYPARK_LOCKOUT_AFTER', '5'))
    _LOCKOUT_SECONDS = int(os.environ.get('MOBYPARK_LOCKOUT_SECONDS', '300'))

    _ip_attempts: dict = {}
    _user_attempts: dict = {}
    _ip_lockouts: dict = {}
    _user_lockouts: dict = {}

    _FORMAT_REGEX = {
        'username': re.compile(r'^[A-Za-z0-9_.-]{3,32}$'),
        'role': re.compile(r'^(USER|ADMIN)$'),
        'licenseplate': re.compile(r'^[A-Z0-9-]{2,12}$'),
        'transaction': re.compile(r'^[A-Za-z0-9:_-]{1,128}$'),
    }

    _FIELD_MAXLEN = {
        'username': 32,
        'name': 100,
        'role': 5,
        'licenseplate': 16,
        'transaction': 128,
        'password': 256,
    }

    def _audit(self, session_user, action, *, target=None, extra=None, status="SUCCESS"):
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

    def _hash_password(self, password: str) -> str:
        try:
            bcrypt = importlib.import_module("bcrypt")
        except ImportError as exc:
            raise RuntimeError("bcrypt is not installed. Please install with: pip install bcrypt") from exc
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
            try:
                bcrypt = importlib.import_module("bcrypt")
            except ImportError as exc:
                raise RuntimeError("bcrypt is not installed. Please install with: pip install bcrypt") from exc
            return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
        if self._looks_like_md5(stored_hash):
            return hashlib.md5(plain_password.encode()).hexdigest() == stored_hash
        return False

    def _authorize_admin(self, session_user):
        return session_user.get("role") == "ADMIN"

    def __init__(self, *args, **kwargs):
        self.routes = {
            'POST': {
                '/register': self._handle_register,
                '/login': self._handle_login,
                '/parking-lots': self._handle_create_parking_lot,
                '/reservations': self._handle_create_reservation,
                '/vehicles': self._handle_create_vehicle,
                '/payments': self._handle_create_payment,
                '/parking-lots/sessions/start': self._handle_start_session,
                '/parking-lots/sessions/stop': self._handle_stop_session,
                '/payments/refund': self._handle_refund_payment,
            },
            'PUT': {
                '/profile': self._handle_update_profile,
                '/parking-lots/': self._handle_update_parking_lot,
                '/reservations/': self._handle_update_reservation,
                '/vehicles/': self._handle_update_vehicle,
                '/payments/': self._handle_update_payment,
            },
            'GET': {
                '/profile': self._handle_get_profile,
                '/logout': self._handle_logout,
                '/parking-lots': self._handle_get_parking_lots,
                '/reservations': self._handle_get_reservations,
                '/payments': self._handle_get_payments,
                '/billing': self._handle_get_billing,
                '/vehicles': self._handle_get_vehicles,
                '/parking-lots/': self._handle_get_parking_lot_details,
                '/reservations/': self._handle_get_reservation_details,
                '/payments/': self._handle_get_payment_details,
                '/billing/': self._handle_get_user_billing,
                '/vehicles/': self._handle_get_vehicle_details,
                '/vehicles/reservations': self._handle_get_vehicle_reservations,
                '/vehicles/history': self._handle_get_vehicle_history,
                '/parking-lots/sessions': self._handle_get_parking_lot_sessions,
                '/': self._handle_index,
                '/index': self._handle_index,
                '/index.html': self._handle_index,
                '/favicon.ico': self._handle_favicon,
            },
            'DELETE': {
                '/parking-lots/': self._handle_delete_parking_lot,
                '/reservations/': self._handle_delete_reservation,
                '/vehicles/': self._handle_delete_vehicle,
                '/parking-lots/sessions/': self._handle_delete_session,
            }
        }
        super().__init__(*args, **kwargs)

    def _send_response(self, status_code, content_type, data):
        self.send_response(status_code)
        self.send_header("Content-type", content_type)
        self._apply_security_headers()
        self.end_headers()
        if content_type == "application/json":
            if not isinstance(data, (dict, list)):
                data = {"message": data} if isinstance(data, str) else {"value": data}
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
        else:
            self.wfile.write(str(data).encode('utf-8'))

    def _get_request_data(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        if content_length > self._MAX_JSON_BYTES:
            _ = self.rfile.read(min(content_length, self._MAX_JSON_BYTES))
            return {}
        raw = self.rfile.read(content_length)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(parsed, dict):
            return {}
        return parsed

    def _strip_unsafe_string(self, value: str, max_length: int) -> str:
        cleaned = re.sub(r"[\x00-\x1F\x7F]", "", value)
        cleaned = cleaned.strip()
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length]
        return cleaned

    def do_POST(self):
        # if self._enforce_https():
        #     return
        self._dispatch_request('POST')

    def do_PUT(self):
        # if self._enforce_https():
        #     return
        self._dispatch_request('PUT')

    def do_DELETE(self):
        # if self._enforce_https():
        #     return
        self._dispatch_request('DELETE')

    def do_GET(self):
        # if self._enforce_https():
        #     return
        self._dispatch_request('GET')

    def do_OPTIONS(self):
        if self._enforce_https():
            return
        self.send_response(204)
        self._apply_security_headers()
        origin = self.headers.get('Origin')
        if self._is_origin_allowed(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers')
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('Access-Control-Allow-Methods', self._CORS_ALLOW_METHODS)
            req_headers = self.headers.get('Access-Control-Request-Headers') or self._CORS_ALLOW_HEADERS
            self.send_header('Access-Control-Allow-Headers', req_headers)
            self.send_header('Access-Control-Max-Age', '600')
        self.end_headers()

    def _dispatch_request(self, method):
        # Prioritize exact matches
        if self.path in self.routes[method]:
            self.routes[method][self.path]()
            return
        
        # Then check for prefix matches (e.g., /parking-lots/123)
        for path_prefix, handler in self.routes[method].items():
            if path_prefix.endswith('/') and self.path.startswith(path_prefix):
                handler()
                return

        self._send_response(404, "application/json", {"error": "Not Found"})

    def _now(self):
        return int(time.time())

    def _client_ip(self):
        if self._TRUST_PROXY:
            xff = self.headers.get('X-Forwarded-For')
            if xff:
                return xff.split(',')[0].strip()
        return self.client_address[0] if self.client_address else 'unknown'

    def _prune_old(self, entries):
        cutoff = self._now() - self._RL_WINDOW_SEC
        return [t for t in entries if t >= cutoff]

    def _check_rate_limits_and_lockouts(self, username):
        now = self._now()
        ip = self._client_ip()

        ip_until = self._ip_lockouts.get(ip)
        if isinstance(ip_until, int) and ip_until > now:
            return True, max(1, ip_until - now), {"error": "Too many attempts from IP. Try later."}
        user_until = self._user_lockouts.get(username)
        if isinstance(user_until, int) and user_until > now:
            return True, max(1, user_until - now), {"error": "Account temporarily locked. Try later."}

        ip_entries = self._prune_old(self._ip_attempts.get(ip, []))
        self._ip_attempts[ip] = ip_entries
        if len(ip_entries) >= self._RL_IP_MAX:
            retry_after = max(1, (ip_entries[0] + self._RL_WINDOW_SEC) - now)
            return True, retry_after, {"error": "Rate limit exceeded for IP."}

        user_entries = self._prune_old(self._user_attempts.get(username, []))
        self._user_attempts[username] = user_entries
        if len(user_entries) >= self._RL_USER_MAX:
            retry_after = max(1, (user_entries[0] + self._RL_WINDOW_SEC) - now)
            return True, retry_after, {"error": "Rate limit exceeded for user."}

        return False, 0, None

    def _record_login_attempt(self, username, success):
        now = self._now()
        ip = self._client_ip()
        if success:
            self._user_attempts.pop(username, None)
            self._ip_attempts[ip] = self._prune_old(self._ip_attempts.get(ip, []))
            return
        ip_entries = self._prune_old(self._ip_attempts.get(ip, []))
        ip_entries.append(now)
        self._ip_attempts[ip] = ip_entries

        user_entries = self._prune_old(self._user_attempts.get(username, []))
        user_entries.append(now)
        self._user_attempts[username] = user_entries

        if self._LOCKOUT_AFTER > 0 and len(user_entries) >= self._LOCKOUT_AFTER:
            self._user_lockouts[username] = now + self._LOCKOUT_SECONDS
        if self._LOCKOUT_AFTER > 0 and len(ip_entries) >= self._LOCKOUT_AFTER:
            self._ip_lockouts[ip] = now + self._LOCKOUT_SECONDS

    def _is_origin_allowed(self, origin):
        if not origin:
            return False
        if not self._CORS_ORIGINS:
            return False
        return origin in self._CORS_ORIGINS

    def _is_secure(self):
        if self._TRUST_PROXY:
            xfproto = self.headers.get('X-Forwarded-Proto')
            if xfproto and 'https' in xfproto.split(',')[0].strip().lower():
                return True
            forwarded = self.headers.get('Forwarded')
            if forwarded and 'proto=https' in forwarded.lower():
                return True
        return False

    def _enforce_https(self):
        print(f"DEBUG: _FORCE_HTTPS={self._FORCE_HTTPS}, _is_secure()={self._is_secure()}")
        if self._FORCE_HTTPS and not self._is_secure():
            host = self.headers.get('Host', 'localhost')
            location = f"https://{host}{self.path}"
            self.send_response(308)
            self.send_header('Location', location)
            self.send_header('Content-Length', '0')
            self._apply_security_headers()
            self.end_headers()
            return True
        return False

    def _apply_security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Resource-Policy', 'same-site')
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
        self.send_header('Content-Security-Policy', csp)

        origin = self.headers.get('Origin')
        if self._is_origin_allowed(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
            self.send_header('Access-Control-Allow-Credentials', 'true')

    def _get_user_from_session(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return None
        try:
            scheme, token = auth_header.split(' ', 1)
            if scheme.lower() != 'bearer':
                return None
            session_data = get_session(token)
            return session_data.get('user') if session_data else None
        except ValueError:
            return None

    def _validate_data(self, data, required_fields=None, optional_fields=None, allow_unknown=False):
        if required_fields is None:
            required_fields = {}
        if optional_fields is None:
            optional_fields = {}

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

        if 'password' in data and isinstance(data['password'], str):
            if len(data['password']) < 8:
                return False, {"error": "Password must be at least 8 characters", "field": "password"}

        for df in ('startdate', 'enddate'):
            if df in data and isinstance(data[df], str):
                ok = True
                try:
                    datetime.strptime(data[df], "%Y-%m-%d")
                except ValueError:
                    try:
                        datetime.strptime(data[df], "%d-%m-%Y")
                    except ValueError:
                        ok = False
                if not ok:
                    return False, {"error": "Invalid date format", "field": df}

        return True, None

    def _handle_register(self):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'username': str, 'password': str, 'name': str},
            optional_fields={'role': str}
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        username = data['username']
        password = data['password']
        name = data['name']
        
        if not isinstance(password, str) or not password:
            self._send_response(400, "application/json", {"error": "Invalid password", "field": "password"})
            return
        
        hashed_password = self._hash_password(password)
        users = load_json('users.json')
        
        if any(user['username'] == username for user in users):
            self._send_response(409, "application/json", {"error": "Username already taken"})
            return
        
        new_id = str(max(int(u.get("id", 0)) for u in users) + 1) if users else "1"
        users.append({
            'id': new_id,
            'username': username,
            'password': hashed_password,
            'name': name,
            'role': data.get('role', 'USER'),
            'created_at': datetime.now().strftime("%Y-%m-%d")
        })
        save_user_data(users)
        self._send_response(201, "application/json", {"message": "User created"})

    def _handle_login(self):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data,\
            required_fields={'username': str, 'password': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
            
        username = data['username']
        password = data['password']

        limited, retry_after, err = self._check_rate_limits_and_lockouts(username)
        if limited:
            self.send_response(429)
            self.send_header("Content-type", "application/json")
            self.send_header("Retry-After", str(retry_after))
            self._apply_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps(err).encode('utf-8'))
            return
        
        users = load_json('users.json')
        user = next((u for u in users if u.get("username") == username), None)
        if user and self._verify_password(password, user.get("password", "")):
            if self._looks_like_md5(user.get("password", "")):
                new_hash = self._hash_password(password)
                user["password"] = new_hash
                for i, uu in enumerate(users):
                    if uu.get("username") == username:
                        users[i] = user
                        break
                save_user_data(users)
            token = str(uuid.uuid4())
            add_session(token, user)
            self._record_login_attempt(username, True)
            self._send_response(200, "application/json", {"message": "User logged in", "session_token": token})
        else:
            self._record_login_attempt(username, False)
            self._send_response(401, "application/json", {"error": "Invalid credentials"})

    @login_required
    @roles_required(['ADMIN'])
    def _handle_create_parking_lot(self, session_user):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'name': str, 'location': str, 'capacity': int, 'hourly_rate': (int, float), 'day_rate': (int, float)}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        parking_lots = load_parking_lot_data()
        new_lid = str(len(parking_lots) + 1)
        parking_lots[new_lid] = {
            "id": new_lid,
            "name": data['name'],
            "location": data['location'],
            "capacity": data['capacity'],
            "hourly_rate": data['hourly_rate'],
            "day_rate": data['day_rate'],
            "reserved": 0
        }
        save_parking_lot_data(parking_lots)
        self._audit(session_user, action="create_parking_lot", target=new_lid, extra={"name": data['name']})
        self._send_response(201, "application/json", {"message": f"Parking lot saved under ID: {new_lid}"})

    @login_required
    def _handle_start_session(self, session_user):
        lid = self.path.split("/")[2]
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        filtered = {key: value for key, value in sessions.items() if value.get("licenseplate") == data['licenseplate'] and not value.get('stopped')}
        
        if len(filtered) > 0:
            self._send_response(409, "application/json", {"error": "Cannot start a session when another session for this license plate is already started."})
            return 
        
        session = {
            "licenseplate": data['licenseplate'],
            "started": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            "stopped": None,
            "user": session_user["username"]
        }
        sessions[str(len(sessions) + 1)] = session
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self._send_response(200, "application/json", {"message": f"Session started for: {data['licenseplate']}"})

    @login_required
    def _handle_stop_session(self, session_user):
        lid = self.path.split("/")[2]
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        filtered = {key: value for key, value in sessions.items() if value.get("licenseplate") == data['licenseplate'] and not value.get('stopped')}
        
        if len(filtered) == 0:
            self._send_response(409, "application/json", {"error": "Cannot stop a session when there is no session for this license plate."})
            return
        
        sid = next(iter(filtered))
        sessions[sid]["stopped"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self._send_response(200, "application/json", {"message": f"Session stopped for: {data['licenseplate']}"})

    @login_required
    def _handle_create_reservation(self, session_user):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str, 'startdate': str, 'enddate': str, 'parkinglot': str},
            optional_fields={'user': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        reservations = load_reservation_data()
        parking_lots = load_parking_lot_data()
        
        if data['parkinglot'] not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found", "field": "parkinglot"})
            return
        
        if self._authorize_admin(session_user):
            if "user" not in data:
                self._send_response(400, "application/json", {"error": "Required field missing", "field": "user"})
                return
        else:
            data["user"] = session_user["username"]
        
        rid = str(len(reservations) + 1)
        reservations[rid] = data
        data["id"] = rid
        parking_lots[data["parkinglot"]]["reserved"] += 1
        save_reservation_data(reservations)
        save_parking_lot_data(parking_lots)
        self._send_response(201, "application/json", {"status": "Success", "reservation": data})

    @login_required
    def _handle_create_vehicle(self, session_user):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str},
            optional_fields={'name': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        vehicles = self._load_vehicles()
        users = load_json('users.json')
        current_user = next((u for u in users if u.get('username') == session_user['username']), None)
        
        if not current_user:
            self._send_response(404, "application/json", {"error": "User not found"})
            return
        
        user_vehicles = vehicles.get(current_user["username"], [])
        if any(v for v in user_vehicles if v.get('license_plate') == data['licenseplate']):
            self._send_response(409, "application/json", {"error": "Vehicle already exists for this user"})
            return
        
        new_vid = str(uuid.uuid4())
        vehicle = {
            "id": new_vid,
            "user_id": current_user.get('id'),
            "license_plate": data['licenseplate'],
            "name": data.get("name"),
            "created_at": datetime.now().strftime("%Y-%m-%d")
        }
        user_vehicles.append(vehicle)
        vehicles[current_user["username"]] = user_vehicles
        self._save_vehicles(vehicles)
        self._send_response(201, "application/json", {"status": "Success", "vehicle": vehicle})

    @login_required
    def _handle_create_payment(self, session_user):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'transaction': str, 'amount': (int, float)}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        payments = load_payment_data()
        
        payment = {
            "transaction": data['transaction'],
            "amount": data['amount'],
            "initiator": session_user["username"],
            "created_at": datetime.now().strftime("%d-%m-%Y %H:%I:%S"),
            "completed": False,
            "hash": sc.generate_transaction_validation_hash()
        }
        payments.append(payment)
        save_payment_data(payments)
        self._audit(session_user, action="refund_payment", target=payment["transaction"], extra={"amount": payment["amount"], "coupled_to": payment.get("coupled_to")})
        self._send_response(201, "application/json", {"status": "Success", "payment": payment})

    @login_required
    @roles_required(['ADMIN'])
    def _handle_refund_payment(self, session_user):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data,\
            required_fields={'amount': (int, float)},\
            optional_fields={'transaction': str, 'coupled_to': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        payments = load_payment_data()
        payment = {
            "transaction": data.get("transaction") if data.get("transaction") else sc.generate_payment_hash(session_user["username"], str(datetime.now())),
            "amount": -abs(data['amount']),
            "coupled_to": data.get("coupled_to"),
            "processed_by": session_user["username"],
            "created_at": datetime.now().strftime("%d-%m-%Y %H:%I:%S"),
            "completed": False,
            "hash": sc.generate_transaction_validation_hash()
        }
        payments = load_payment_data()
        refund_txn = data.get("transaction") if data.get("transaction") else str(uuid.uuid4())
        payment = {
            "transaction": refund_txn,
            "amount": -abs(data['amount']),
            "coupled_to": data.get("coupled_to"),
            "processed_by": session_user["username"],
            "created_at": datetime.now().strftime("%d-%m-%Y %H:%I:%S"),
            "completed": False,
            "hash": sc.generate_transaction_validation_hash()
        }
        payments.append(payment)
        save_payment_data(payments)
        self._send_response(201, "application/json", {"status": "Success", "payment": payment})

    @login_required
    def _handle_update_profile(self, session_user):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data,\
            optional_fields={'name': str, 'password': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return

        data["username"] = session_user["username"]
        if data.get("password"):
            data["password"] = self._hash_password(data["password"])
        
        users = load_json('users.json')
        updated_user = None
        for i, user in enumerate(users):
            if user.get("username") == session_user["username"]:
                if data.get("name"):
                    users[i]["name"] = data["name"]
                if data.get("password"):
                    users[i]["password"] = data["password"]
                updated_user = users[i]
                break
        save_user_data(users)
        token = self.headers.get('Authorization')
        if updated_user:
            update_session_user(token, updated_user)
        self._send_response(200, "application/json", {"message": "User updated successfully"})

    @login_required
    @roles_required(['ADMIN'])
    def _handle_update_parking_lot(self, session_user):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return
    
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            optional_fields={'name': str, 'location': str, 'capacity': int, 'hourly_rate': (int, float), 'day_rate': (int, float), 'reserved': int}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        parking_lots[lid] = data
        save_parking_lot_data(parking_lots)
        self._audit(session_user, action="update_parking_lot", target=lid)
        self._send_response(200, "application/json", {"message": "Parking lot modified"})

    @login_required
    def _handle_update_reservation(self, session_user):
        data = self._get_request_data()
        reservations = load_reservation_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_response(404, "application/json", {"error": "Reservation not found"})
            return
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str, 'startdate': str, 'enddate': str, 'parkinglot': str},
            optional_fields={'user': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        if self._authorize_admin(session_user):
            if "user" not in data:
                self._send_response(400, "application/json", {"error": "Required field missing", "field": "user"})
            else:
                data["user"] = session_user["username"]
        else:
            data["user"] = session_user["username"]
        
        reservations[rid] = data
        save_reservation_data(reservations)
        self._send_response(200, "application/json", {"status": "Updated", "reservation": data})

    @login_required
    def _handle_update_vehicle(self, session_user):
        data = self._get_request_data()
        
        valid, error = self._validate_data(data,\
            required_fields={'name': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        vehicles = self._load_vehicles()
        
        vid = self.path.replace("/vehicles/", "")
        
        user_vehicles = vehicles.get(session_user["username"])
        if not user_vehicles:
            self._send_response(404, "application/json", {"error": "User vehicles not found"})
            return
        
        vehicle_found = False
        for i, vehicle in enumerate(user_vehicles):
            if vehicle.get('id') == vid:
                user_vehicles[i]["name"] = data["name"]
                user_vehicles[i]["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                vehicle_found = True
                break
        
        if not vehicle_found:
            self._send_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        vehicles[session_user["username"]] = user_vehicles
        self._save_vehicles(vehicles)
        self._send_response(200, "application/json", {"status": "Success", "vehicle": next(v for v in user_vehicles if v.get('id') == vid)})

    @login_required
    def _handle_update_payment(self, session_user):
        pid = self.path.replace("/payments/", "")
        payments = load_payment_data()
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'t_data': dict, 'validation': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        payment = next((p for p in payments if p["transaction"] == pid), None)
        
        if not payment:
            self._send_response(404, "application/json", {"error": "Payment not found!"})
            return
        
        if payment["hash"] != data['validation']:
            self._send_response(401, "application/json", {"error": "Validation failed", "info": "The validation of the security hash could not be validated for this transaction."})
            return  
        
        payment["completed"] = datetime.now().strftime("%d-%m-%Y %H:%I:%S")
        payment["t_data"] = data['t_data']
        save_payment_data(payments)
        self._send_response(200, "application/json", {"status": "Success", "payment": payment})

    @login_required
    @roles_required(['ADMIN'])
    def _handle_delete_parking_lot(self, session_user):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return

        del parking_lots[lid]
        save_parking_lot_data(parking_lots)
        self._audit(session_user, action="delete_parking_lot", target=lid)
        self._send_response(200, "application/json", {"message": "Parking lot deleted"})

    @login_required
    @roles_required(['ADMIN'])
    def _handle_delete_session(self, session_user):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return
        
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        sid = self.path.split("/")[-1]
        
        if not sid.isnumeric():
            self._send_response(400, "application/json", {"error": "Session ID is required, cannot delete all sessions"})
            return
                
        if sid not in sessions:
            self._send_response(404, "application/json", {"error": "Session not found"})
            return
        
        del sessions[sid]
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self._audit(session_user, action="delete_session", target={"parking_lot": lid, "session": sid})
        self._send_response(200, "application/json", {"message": "Session deleted"})

    @login_required
    def _handle_delete_reservation(self, session_user):
        reservations = load_reservation_data()
        parking_lots = load_parking_lot_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_response(404, "application/json", {"error": "Reservation not found"})
            return
        
        if not self._authorize_admin(session_user) and not session_user["username"] == reservations[rid].get("user"):
            self._send_response(403, "application/json", {"error": "Access denied"})
            return
        
        reservation_to_delete = reservations[rid]
        pid = reservation_to_delete["parkinglot"]
        
        if parking_lots[pid]["reserved"] > 0:
            parking_lots[pid]["reserved"] -= 1
        else:
            self._send_response(400, "application/json", {"error": "Parking lot reserved count is already zero"})
            return

        del reservations[rid]
        save_reservation_data(reservations)
        save_parking_lot_data(parking_lots)
        self._send_response(200, "application/json", {"status": "Deleted"})

    @login_required
    def _handle_delete_vehicle(self):
        vid = self.path.replace("/vehicles/", "")
        

        
        session_user = self._get_user_from_session()
        vehicles = self._load_vehicles()
        user_vehicles = vehicles.get(session_user["username"])
        
        if not user_vehicles:
            self._send_response(404, "application/json", {"error": "User vehicles not found"})
            return
        
        original_len = len(user_vehicles)
        user_vehicles = [v for v in user_vehicles if v.get('id') != vid]
        
        if len(user_vehicles) == original_len:
            self._send_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        vehicles[session_user["username"]] = user_vehicles
        save_data("vehicles.json", vehicles)
        self._audit(session_user, action="delete_vehicle", target=vid)
        self._send_response(200, "application/json", {"status": "Deleted"})

    @login_required
    def _handle_index(self):
        self._send_response(200, "text/html; charset=utf-8", 
            "<html><head><title>MobyPark API</title></head>"
            "<body>"
            "<h1>MobyPark API is running</h1>"
            "<p>Try endpoints like <code>/parking-lots</code>, <code>/profile</code> (requires Authorization), etc.</p>"
            "</body></html>"
        )

    def _handle_favicon(self):
        self._send_response(204, "image/x-icon", "")

    def _handle_get_parking_lots(self):
        parking_lots = load_parking_lot_data()
        self._send_response(200, "application/json", parking_lots)

    @login_required
    def _handle_get_profile(self):

        
        session_user = self._get_user_from_session()
        allowed_keys = {"id", "username", "name", "role", "created_at"}
        profile_data = {k: v for k, v in session_user.items() if k in allowed_keys}
        self._send_response(200, "application/json", profile_data)

    def _handle_logout(self):
        token = self.headers.get('Authorization')
        if token and get_session(token):
            remove_session(token)
            self._send_response(200, "application/json", {"message": "User logged out"})
        else:
            self._send_response(400, "application/json", {"error": "Invalid session token"})

    def _handle_get_parking_lot_details(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return

        self._send_response(200, "application/json", parking_lots[lid])

    @login_required
    def _handle_get_parking_lot_sessions(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return
        

        
        session_user = self._get_user_from_session()
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        rsessions = []
        
        if self.path.endswith('/sessions'):
            if self._authorize_admin(session_user):
                rsessions = sessions
            else:
                for session in sessions.values():
                    if session['user'] == session_user['username']:
                        rsessions.append(session)
            self._send_response(200, "application/json", rsessions)
        else:
            sid = self.path.split("/")[-1]
            if not self._authorize_admin(session_user) and not session_user["username"] == sessions[sid].get("user"):
                self._send_response(403, "application/json", {"error": "Access denied"})
                return
            self._send_response(200, "application/json", sessions[sid])

    @login_required
    def _handle_get_reservations(self):

        
        session_user = self._get_user_from_session()
        reservations = load_reservation_data()
        user_reservations = {rid: res for rid, res in reservations.items() if res.get("user") == session_user["username"] or session_user.get("role") == "ADMIN"}
        self._send_response(200, "application/json", user_reservations)

    @login_required
    def _handle_get_reservation_details(self):
        reservations = load_reservation_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_response(404, "application/json", {"error": "Reservation not found"})
            return
                

        
        session_user = self._get_user_from_session()
        if not self._authorize_admin(session_user) and not session_user["username"] == reservations[rid].get("user"):
            self._send_response(403, "application/json", {"error": "Access denied"})
            return
        
        self._send_response(200, "application/json", reservations[rid])

    @login_required
    def _handle_get_payments(self):

        
        session_user = self._get_user_from_session()
        payments = []
        for payment in load_payment_data():
            if payment.get("initiator") == session_user["username"] or payment.get("processed_by") == session_user["username"] or session_user.get("role") == "ADMIN":
                payments.append(payment)
        self._send_response(200, "application/json", payments)

    @login_required
    def _handle_get_payment_details(self):

        
        pid = self.path.replace("/payments/", "")
        payments = load_payment_data()
        
        payment = next((p for p in payments if p["transaction"] == pid), None)
        
        if not payment:
            self._send_response(404, "application/json", {"error": "Payment not found!"})
            return
        
        session_user = self._get_user_from_session()
        if not self._authorize_admin(session_user) and not (payment.get("initiator") == session_user["username"] or payment.get("processed_by") == session_user["username"]):
            self._send_response(403, "application/json", {"error": "Access denied"})
            return

        self._send_response(200, "application/json", payment)

    @login_required
    def _handle_get_billing(self):
        
        session_user = self._get_user_from_session()
        data = []
        for pid, parkinglot in load_parking_lot_data().items():
            try:
                sessions = load_json(f'pdata/p{pid}-sessions.json')
            except FileNotFoundError:
                sessions = {}
            for sid, session in sessions.items():
                if session["user"] == session_user["username"]:
                    amount, hours, days = sc.calculate_price(parkinglot, sid, session)
                    transaction = sc.generate_payment_hash(sid, session)
                    payed = sc.check_payment_amount(transaction)
                    data.append({
                        "session": {k: v for k, v in session.items() if k in ["licenseplate", "started", "stopped"]} | {"hours": hours, "days": days},
                        "parking": {k: v for k, v in parkinglot.items() if k in ["name", "location", "tariff", "daytariff"]},
                        "amount": amount,
                        "thash": transaction,
                        "payed": payed,
                        "balance": amount - payed
                    })
        self._send_response(200, "application/json", data)

    def _load_vehicles(self):
        vehicles = load_json("vehicles.json")
        if isinstance(vehicles, dict):
            return vehicles
        return {}

    def _save_vehicles(self, vehicles):
        save_data("vehicles.json", vehicles)

    @login_required
    @roles_required(['ADMIN'])
    def _handle_get_user_billing(self):
        
        
        user = self.path.replace("/billing/", "")
        data = []
        for pid, parkinglot in load_parking_lot_data().items():
            try:
                sessions = load_json(f'pdata/p{pid}-sessions.json')
            except FileNotFoundError:
                sessions = {}
            for sid, session in sessions.items():
                if session["user"] == user:
                    amount, hours, days = sc.calculate_price(parkinglot, sid, session)
                    transaction = sc.generate_payment_hash(sid, session)
                    payed = sc.check_payment_amount(transaction)
                    data.append({
                        "session": {k: v for k, v in session.items() if k in ["licenseplate", "started", "stopped"]} | {"hours": hours, "days": days},
                        "parking": {k: v for k, v in parkinglot.items() if k in ["name", "location", "tariff", "daytariff"]},
                        "amount": amount,
                        "thash": transaction,
                        "payed": payed,
                        "balance": amount - payed
                    })
        self._send_response(200, "application/json", data)

    @login_required
    def _handle_get_vehicles(self):
        
        session_user = self._get_user_from_session()
        vehicles = load_json("vehicles.json")
        
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.startswith("/vehicles/"):
            parts = self.path.split('/')
            if len(parts) > 2 and parts[2]:
                target_user = parts[2]
            else:
                all_vehicles = []
                for user_v_list in vehicles.values():
                    all_vehicles.extend(user_v_list)
                self._send_response(200, "application/json", all_vehicles)
                return
        
        if target_user not in vehicles:
            self._send_response(404, "application/json", {"error": "User or their vehicles not found"})
            return
        
        self._send_response(200, "application/json", vehicles.get(target_user, {}))

    @login_required
    def _handle_get_vehicle_reservations(self):
        
        vid = self.path.split("/")[2]
        
        session_user = self._get_user_from_session()
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.count('/') > 3:
            parts = self.path.split('/')
            if parts[2] and parts[2] != vid:
                target_user = parts[2]
                vid = parts[3]
            else:
                self._send_response(400, "application/json", {"error": "Invalid vehicle reservations request"})
                return
        
        vehicles = self._load_vehicles()
        user_vehicles = vehicles.get(target_user)
        
        if not user_vehicles:
            self._send_response(404, "application/json", {"error": "User or vehicle not found"})
            return
            
        vehicle = next((v for v in user_vehicles if v.get('id') == vid), None)
        if not vehicle:
            self._send_response(404, "application/json", {"error": "Vehicle not found"})
            return
            
        reservations = load_reservation_data()
        vehicle_reservations = [res for res in reservations.values() if res.get('licenseplate') == vehicle['license_plate'] and res.get('user') == target_user]
        
        self._send_response(200, "application/json", vehicle_reservations)

    @login_required
    def _handle_get_vehicle_history(self):
        
        vid = self.path.split("/")[2]
        
        session_user = self._get_user_from_session()
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.count('/') > 2:
            parts = self.path.split('/')
            if parts[2] and parts[2] != vid:
                target_user = parts[2]
                vid = parts[3]
            elif parts[2] and parts[2] == vid:
                pass
            else:
                self._send_response(400, "application/json", {"error": "Invalid vehicle history request"})
                return
        
        vehicles = self._load_vehicles()
        user_vehicles = vehicles.get(target_user)
        
        if not user_vehicles:
            self._send_response(404, "application/json", {"error": "User or vehicle not found"})
            return
            
        vehicle = next((v for v in user_vehicles if v.get('id') == vid), None)
        if not vehicle:
            self._send_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        all_sessions = []
        for pid, _ in load_parking_lot_data().items():
            try:
                sessions = load_json(f'pdata/p{pid}-sessions.json')
                for _, session in sessions.items():
                    if session.get('licenseplate') == vehicle['license_plate'] and session.get('user') == target_user:
                        all_sessions.append(session)
            except FileNotFoundError:
                continue
        
        self._send_response(200, "application/json", all_sessions)

    @login_required
    def _handle_get_vehicle_details(self):
        
        vid = self.path.replace("/vehicles/", "").replace("/entry", "")
        vehicles = load_json("vehicles.json")
        
        session_user = self._get_user_from_session()
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.count('/') > 2:
            parts = self.path.split('/')
            if parts[2] and parts[2] != vid:
                target_user = parts[2]
                vid = parts[3] if len(parts) > 3 else vid
            elif parts[2] and parts[2] == vid:
                pass
            else:
                self._send_response(400, "application/json", {"error": "Invalid vehicle details request"})
                return
        
        user_vehicles = vehicles.get(target_user)
        if not user_vehicles:
            self._send_response(404, "application/json", {"error": "User or vehicle not found"})
            return
        
        vehicle = next((v for v in user_vehicles if v.get('id') == vid), None)
        
        if not vehicle:
            self._send_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        self._send_response(200, "application/json", {"status": "Accepted", "vehicle": vehicle})

server = HTTPServer(('localhost', 8000), RequestHandler)
print("Server running on http://localhost:8000")
server.serve_forever()