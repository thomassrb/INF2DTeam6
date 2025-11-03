import json
import uuid
from datetime import datetime
import re
import time
import threading
import hashlib

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from storage_utils import load_json, save_data, save_user_data, load_parking_lot_data, save_parking_lot_data, save_reservation_data, load_reservation_data, load_payment_data, save_payment_data
import session_calculator as sc
import authentication


class PasswordManager:
    def hash_password(self, password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

class DataValidator:
    def validate_data(self, _data, _required_fields=None, _optional_fields=None, _allow_unknown=False, **kwargs):
        return True, None 

class AuditLogger:
    def audit(self, user, action, target=None, extra=None):
        pass 

class HTTPSecurity:
    CORS_ALLOW_METHODS = "GET, POST, PUT, DELETE, OPTIONS"
    CORS_ALLOW_HEADERS = "Content-Type, Authorization"

    def enforce_https(self, _handler, _headers, _path):
        return False 

    def apply_security_headers(self, _handler, _headers):
        pass 

    def is_origin_allowed(self, _origin):
        return True 

class SessionManager:
    ''' Beheert de user session, waarbij session token en bijbehorende gebruiksgegevens worden opgeslagen
        Zorgt voor veilige gelijktijdige toegang tot de sessiontoken door gebruik te maken van een threading.Lock,
        zodat er geen fouten ontstaan wanneer meerdere threads tegelijk in de active_sessions-list lezen of schrijven'''
    def __init__(self):
        self.active_sessions = {}
        self.session_lock = threading.Lock()

    def add_session(self, token, user):
        with self.session_lock:
            self.active_sessions[token] = user

    def get_session(self, token):
        with self.session_lock:
            return self.active_sessions.get(token)

    def clear_sessions(self, token):
        with self.session_lock:
            if token in self.active_sessions:
                del self.active_sessions[token]

    def update_session_user(self, token, user_data):
        with self.session_lock:
            if token in self.active_sessions:
                self.active_sessions[token].update(user_data)

def login_required(func):
    def wrapper(self, *args, **kwargs):
        session_user = authentication.get_user_from_session(self)
        if not session_user:
            self._send_json_response(401, "application/json", {"error": "Unauthorized"})
            return
        return func(self, session_user, *args, **kwargs)
    return wrapper

def roles_required(roles):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            session_user = authentication.get_user_from_session(self)
            if not session_user:
                self._send_json_response(401, "application/json", {"error": "Unauthorized"})
                return
            if session_user.get("role") not in roles:
                self._send_json_response(403, "application/json", {"error": "Access denied"})
                return
            return func(self, session_user, *args, **kwargs)
        return wrapper
    return decorator

class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.http_security = HTTPSecurity() 
        self.data_validator = DataValidator()
        self.audit_logger = AuditLogger()  
        self.password_manager = PasswordManager()
        self.session_manager = SessionManager()
        self.last_activity = time.time()
        self.timeout = 300 # 5 mins timeout miss weghalen overbodig?!/
        self.routes = {
            'POST': {
                '/register': lambda: authentication.handle_register(self), # load_tester CHECK!
                '/login': lambda: authentication.handle_login(self), # load_tester CHECK!
                '/parking-lots': self._handle_create_parking_lot, # load_tester CHECK!
                '/reservations': self._handle_create_reservation,
                '/vehicles': self._handle_create_vehicle,
                '/payments': self._handle_create_payment,
                '/parking-lots/sessions/start': self._handle_start_session,
                '/parking-lots/sessions/stop': self._handle_stop_session,
                '/payments/refund': self._handle_refund_payment,
                '/debug/reset': self._handle_debug_reset, # hier nog even naar kijken
            },
            'PUT': {
                '/profile': lambda: authentication.handle_update_profile(self, self.get_user_from_session()),
                '/parking-lots/': self._handle_update_parking_lot,
                '/reservations/': self._handle_update_reservation,
                '/vehicles/': self._handle_update_vehicle,
                '/payments/': self._handle_update_payment,
            },
            'GET': {
                '/': self._handle_index,
                '/index': self._handle_index,
                '/index.html': self._handle_index,
                '/favicon.ico': self._handle_favicon,
                '/parking-lots': self._handle_get_parking_lots,
                '/profile': lambda: authentication.handle_get_profile(self, self.get_user_from_session()),
                '/logout': lambda: authentication.handle_logout(self),
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
                '/profile/': lambda: authentication.handle_get_profile_by_id(self, self.get_user_from_session()),
            },
            'DELETE': {
                '/parking-lots/': self._handle_delete_parking_lot,
                '/reservations/': self._handle_delete_reservation,
                '/vehicles/': self._handle_delete_vehicle,
                '/parking-lots/sessions/': self._handle_delete_session,
            }
        }
        super().__init__(*args, **kwargs)

    def _send_json_response(self, status_code, content_type, data):
        super().send_response(status_code)
        self.send_header("Content-type", content_type)
        self.end_headers()
        if isinstance(data, dict) or isinstance(data, list):
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
        else:
            self.wfile.write(str(data).encode('utf-8'))

    def get_request_data(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return json.loads(self.rfile.read(content_length))
        return {}
    
    # nieuwe functie voor de Responstijd ≤ 300 ms per request,
    # de reden dat functie naam met _ begint is omdat het niet bij de api hoort, private method ish
    def _handle_request_with_timing(self, method):
        start_time = time.time()
        try:
            if self.http_security.enforce_https(self, self.headers, self.path):
                return
            self.dispatch_request(method)
        finally:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            print(f"{method} {self.path} - Response time: {response_time:.2f} ms")

    def do_POST(self):
        self._handle_request_with_timing('POST')

    def do_PUT(self):
        self._handle_request_with_timing('PUT')
   
    def do_DELETE(self):
        self._handle_request_with_timing('DELETE')

    def do_GET(self):
        self._handle_request_with_timing('GET')

    def do_OPTIONS(self):
        if self.http_security.enforce_https(self, self.headers, self.path):
            return
        super().send_response(204)
        self.http_security.apply_security_headers(self, self.headers)
        origin = self.headers.get('Origin')
        if self.http_security.is_origin_allowed(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers')
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('Access-Control-Allow-Methods', self.http_security.CORS_ALLOW_METHODS)
            req_headers = self.headers.get('Access-Control-Request-Headers') or self.http_security.CORS_ALLOW_HEADERS
            self.send_header('Access-Control-Allow-Headers', req_headers)
            self.send_header('Access-Control-Max-Age', '600')
        self.end_headers()

    def dispatch_request(self, method):
        if self.path in self.routes[method]:
            self.routes[method][self.path]()
            return

        for k, handler in self.routes[method].items():
            if isinstance(k, re.Pattern) and k.match(self.path):
                handler()
                return

        for path_prefix, handler in self.routes[method].items():
            if isinstance(path_prefix, str) and path_prefix != '/' and path_prefix.endswith('/') and self.path.startswith(path_prefix):
                handler()
                return
            elif isinstance(path_prefix, str) and not path_prefix.endswith('/') and self.path == path_prefix:
                handler()
                return

        allowed_methods = []
        for m, routes in self.routes.items():
            for path_prefix in routes:
                if (isinstance(path_prefix, str) and self.path.startswith(path_prefix) and path_prefix.endswith('/')) or \
                   (isinstance(path_prefix, str) and self.path == path_prefix and not path_prefix.endswith('/')):
                    allowed_methods.append(m)
                elif isinstance(path_prefix, re.Pattern) and path_prefix.match(self.path):
                    allowed_methods.append(m)


        if allowed_methods:
            self._send_json_response(405, "application/json", {"error": "Method Not Allowed"})
            self.send_header("Allow", ", ".join(allowed_methods))
            self.end_headers()
            return

        self._send_json_response(404, "application/json", {"error": "Not Found"})

    def _handle_create_parking_lot(self):
        data = self.get_request_data()

        required_fields = ['name', 'location', 'capacity', 'tariff', 'daytariff', 'address', 'coordinates']
        for field in required_fields:
            if field not in data or not isinstance(data[field], str) or not data[field].strip():
                self._send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
                return

        if not isinstance(data['capacity'], int) or data['capacity'] <= 0:
            self._send_json_response(400, "application/json", {"error": "Capacity must be a positive integer", "field": "capacity"})
            return
        if not isinstance(data['tariff'], (int, float)) or data['tariff'] < 0:
            self._send_json_response(400, "application/json", {"error": "Tariff must be a non-negative number", "field": "tariff"})
            return
        if not isinstance(data['daytariff'], (int, float)) or data['daytariff'] < 0:
            self._send_json_response(400, "application/json", {"error": "Day tariff must be a non-negative number", "field": "daytariff"})
            return
        if not isinstance(data['coordinates'], list) or not all(isinstance(coord, (int, float)) for coord in data['coordinates']) or len(data['coordinates']) != 2:
            self._send_json_response(400, "application/json", {"error": "Coordinates must be a list of two numbers", "field": "coordinates"})
            return

        parking_lots = load_parking_lot_data()
        new_lid = str(len(parking_lots) + 1)
        parking_lots[new_lid] = {
            "id": new_lid,
            "name": data['name'],
            "location": data['location'],
            "capacity": data['capacity'],
            "hourly_rate": data['tariff'],
            "day_rate": data['daytariff'],
            "address": data['address'],
            "coordinates": data['coordinates'],
            "reserved": 0
        }
        save_parking_lot_data(parking_lots)
        self._send_json_response(201, "application/json", {"message": f"Parking lot saved under ID: {new_lid}"})

    @login_required
    def _handle_start_session(self):
        session_user = authentication.get_user_from_session(self)
        if not session_user:
            self._send_json_response(401, "application/json", {"error": "Unauthorized"})
            return
        match = re.match(r"^/parking-lots/([^/]+)/sessions/start$", self.path)
        if not match:
            self._send_json_response(400, "application/json", {"error": "Invalid URL format for starting session"})
            return
        lid = match.group(1)
        data = self.get_request_data()

        if 'licenseplate' not in data or not isinstance(data['licenseplate'], str) or not data['licenseplate'].strip():
            self._send_json_response(400, "application/json", {"error": "Missing or invalid field: licenseplate", "field": "licenseplate"})
            return

        sessions = load_json(f'pdata/p{lid}-sessions.json')
        filtered = {key: value for key, value in sessions.items() if value.get("licenseplate") == data['licenseplate'] and not value.get('stopped')}

        if len(filtered) > 0:
            self._send_json_response(409, "application/json", {"error": "Cannot start a session when another session for this license plate is already started."})
            return 

        session = {
            "licenseplate": data['licenseplate'],
            "started": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            "stopped": None,
            "user": session_user["username"]
        }
        sessions[str(len(sessions) + 1)] = session
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self._send_json_response(200, "application/json", {"message": f"Session started for: {data['licenseplate']}"})

    @login_required
    def _handle_stop_session(self, session_user):
        match = re.match(r"^/parking-lots/([^/]+)/sessions/stop$", self.path)
        if not match:
            self._send_json_response(400, "application/json", {"error": "Invalid URL format for stopping session"})
            return
        lid = match.group(1)
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        filtered = {key: value for key, value in sessions.items() if value.get("licenseplate") == data['licenseplate'] and not value.get('stopped')}
        
        if len(filtered) == 0:
            self._send_json_response(409, "application/json", {"error": "Cannot stop a session when there is no session for this license plate."})
            return
        
        sid = next(iter(filtered))
        sessions[sid]["stopped"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self.audit_logger.audit(session_user, action="stop_session", target=sid, extra={"licenseplate": data['licenseplate'], "parking_lot": lid})
        self._send_json_response(200, "application/json", {"message": f"Session stopped for: {data['licenseplate']}"})

    @login_required
    def _handle_create_reservation(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        reservations = load_reservation_data()
        parking_lots = load_parking_lot_data()
        
        if data['parkinglot'] not in parking_lots:
            self._send_json_response(404, "application/json", {"error": "Parking lot not found", "field": "parkinglot"})
            return
        
        if not (session_user["role"] == "ADMIN"):
            if "user" not in data:
                data["user"] = session_user["username"]
            elif data["user"] != session_user["username"]:
                self._send_json_response(403, "application/json", {"error": "Non-admin users cannot create reservations for other users"})
                return
        else:
            if "user" not in data:
                data["user"] = None

        rid = str(len(reservations) + 1)
        reservations[rid] = data
        data["id"] = rid
        parking_lots[data["parkinglot"]]["reserved"] += 1
        save_reservation_data(reservations)
        save_parking_lot_data(parking_lots)
        self._send_json_response(201, "application/json", {"status": "Success", "reservation": data})

    @login_required
    def _handle_create_vehicle(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        vehicles = self._load_vehicles()
        users = load_json('users.json')
        current_user = next((u for u in users if u.get('username') == session_user['username']), None)
        
        if not current_user:
            self._send_json_response(404, "application/json", {"error": "User not found"})
            return
        
        user_vehicles = vehicles.get(current_user["username"], [])
        if any(v for v in user_vehicles if v.get('license_plate') == data['licenseplate']):
            self._send_json_response(409, "application/json", {"error": "Vehicle already exists for this user"})
            return
        
        new_vid = str(uuid.uuid4())
        vehicle = {
            "id": new_vid,
            "user_id": current_user['id'],
            "license_plate": data['licenseplate'],
            "name": data.get("name"),
            "created_at": datetime.now().strftime("%Y-%m-%d")
        }
        user_vehicles.append(vehicle)
        vehicles[current_user["username"]] = user_vehicles
        self._save_vehicles(vehicles)
        self.audit_logger.audit(session_user, action="create_vehicle", target=new_vid, extra={"license_plate": data['licenseplate']})
        self._send_json_response(201, "application/json", {"status": "Success", "vehicle": vehicle})

    @login_required
    def _handle_create_payment(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        payments = load_payment_data()
        
        payment = {
            "transaction": data['transaction'],
            "amount": data['amount'],
            "initiator": session_user["username"],
            "created_at": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            "completed": False,
            "completed_at": None,
            "hash": sc.generate_transaction_validation_hash()
        }
        payments.append(payment)
        save_payment_data(payments)
        self.audit_logger.audit(session_user, action="create_payment", target=payment["transaction"],extra={"amount": payment["amount"], "coupled_to": payment.get("coupled_to")})
        self._send_json_response(201, "application/json", {"status": "Success", "payment": payment})

  
    @roles_required(['ADMIN'])
    def _handle_refund_payment(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        payments = load_payment_data()
        refund_txn = data.get("transaction") if data.get("transaction") else str(uuid.uuid4())
        payment = {
            "transaction": refund_txn,
            "amount": -abs(data['amount']),
            "coupled_to": data.get("coupled_to"),
            "processed_by": session_user["username"],
            "created_at": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            "completed": False,
            "completed_at": None,
            "hash": sc.generate_transaction_validation_hash()
        }
        payments.append(payment)
        save_payment_data(payments)
        self._send_json_response(201, "application/json", {"status": "Success", "payment": payment})

    @login_required
    def _handle_update_profile_by_id(self, session_user):
        match = re.match(r"^/profile/([^/]+)$", self.path)
        if not match:
            self._send_json_response(400, "application/json", {"error": "Invalid URL format"})
            return
        
        target_user_id = match.group(1)
        
        users = load_json('users.json')
        target_user = next((u for u in users if u.get('id') == target_user_id), None)
        
        if not target_user:
            self._send_json_response(404, "application/json", {"error": "User not found"})
            return
        
        is_admin = session_user["role"] == "ADMIN"
        
        if not is_admin and session_user.get("id") != target_user_id:
            self._send_json_response(403, "application/json", {"error": "Access denied. You can only view your own profile."})
            return
        
        data = self.get_request_data()
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return

        if data.get("password"):
            data["password"] = self.password_manager.hash_password(data["password"])
        
        target_user.update(data)
        save_user_data(users)
        self.audit_logger.audit(session_user, action="update_profile", target=target_user_id)
        self._send_json_response(200, "application/json", {"message": "User updated successfully"})

    
    @roles_required(['ADMIN'])
    def _handle_update_parking_lot(self, session_user):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return
    
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        parking_lots[lid] = data
        pl = parking_lots[lid]
        pl.update(data)
        pl["id"] = lid
        save_parking_lot_data(parking_lots)
        self.audit_logger.audit(session_user, action="update_parking_lot", target=lid)
        self._send_json_response(200, "application/json", {"message": "Parking lot modified"})

    @login_required
    def _handle_update_reservation(self, session_user):
        data = self.get_request_data()
        reservations = load_reservation_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_json_response(404, "application/json", {"error": "Reservation not found"})
            return
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        if session_user["role"] == "ADMIN":
            if "user" not in data:
                data["user"] = session_user["username"]
            elif data["user"] != session_user["username"]:
                self._send_json_response(403, "application/json", {"error": "Non-admin users cannot update reservations for other users"})
                return
        else:
            if "user" in data and data["user"] != session_user["username"]:
                self._send_json_response(403, "application/json", {"error": "Non-admin users cannot update reservations for other users"})
                return
            data["user"] = session_user["username"]
        
        reservations[rid] = data
        save_reservation_data(reservations)
        self._send_json_response(200, "application/json", {"status": "Updated", "reservation": data})

    @login_required
    def _handle_update_vehicle(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        vehicles = self._load_vehicles()
        
        vid = self.path.replace("/vehicles/", "")
        
        user_vehicles = vehicles.get(session_user["username"], [])
        if not user_vehicles:
            self._send_json_response(404, "application/json", {"error": "User vehicles not found"})
            return
        
        vehicle_found = False
        for i, vehicle in enumerate(user_vehicles):
            if vehicle.get('id') == vid:
                user_vehicles[i]["name"] = data["name"]
                user_vehicles[i]["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                vehicle_found = True
                break
        
        if not vehicle_found:
            self._send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        vehicles[session_user["username"]] = user_vehicles
        self._save_vehicles(vehicles)
        self.audit_logger.audit(session_user, action="update_vehicle", target=vid, extra={"name": data["name"]})
        self._send_json_response(200, "application/json", {"status": "Success", "vehicle": next(v for v in user_vehicles if v.get('id') == vid)})

    @login_required
    def _handle_update_payment(self, session_user):
        pid = self.path.replace("/payments/", "")
        payments = load_payment_data()
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self._send_json_response(400, "application/json", error)
            return
        
        payment = next((p for p in payments if p["transaction"] == pid), None)
        
        if not payment:
            self._send_json_response(404, "application/json", {"error": "Payment not found!"})
            return
        
        if payment["hash"] != data['validation']:
            self._send_json_response(401, "application/json", {"error": "Validation failed", "info": "The validation of the security hash could not be validated for this transaction."})
            return

        payment["completed"] = True
        payment["completed_at"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        payment["t_data"] = data['t_data']
        save_payment_data(payments)
        self.audit_logger.audit(session_user, action="update_payment", target=pid)
        self._send_json_response(200, "application/json", {"status": "Success", "payment": payment})

    
    @roles_required(['ADMIN'])
    def _handle_delete_parking_lot(self, session_user):
        lid = None
        path_parts = self.path.split('/')
        if len(path_parts) > 2 and path_parts[2]:
            lid = path_parts[2]

        parking_lots = load_parking_lot_data()

        if lid:
            if lid not in parking_lots:
                self._send_json_response(404, "application/json", {"error": "Parking lot not found"})
                return
            del parking_lots[lid]
            save_parking_lot_data(parking_lots)
            self.audit_logger.audit(session_user, action="delete_parking_lot", target=lid)
            self._send_json_response(200, "application/json", {"message": f"Parking lot {lid} deleted"})
        else:
            save_parking_lot_data({})
            self.audit_logger.audit(session_user, action="delete_all_parking_lots")
            self._send_json_response(200, "application/json", {"message": "All parking lots deleted"})

    
    @roles_required(['ADMIN'])
    def _handle_delete_session(self, session_user):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return
        
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        sid = self.path.split("/")[-1]
        
        if not sid.isnumeric():
            self._send_json_response(400, "application/json", {"error": "Session ID is required, cannot delete all sessions"})
            return
                
        if sid not in sessions:
            self._send_json_response(404, "application/json", {"error": "Session not found"})
            return
        
        del sessions[sid]
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self.audit_logger.audit(session_user, action="delete_session", target={"parking_lot": lid, "session": sid})
        self._send_json_response(200, "application/json", {"message": "Session deleted"})

    @login_required
    def _handle_delete_reservation(self, session_user):
        reservations = load_reservation_data()
        parking_lots = load_parking_lot_data()
        rid = self.path.replace("/reservations/", "")

        if not rid:
            if session_user["role"] == "ADMIN":
                for res_id, reservation in list(reservations.items()):
                    pid = reservation["parkinglot"]
                    if parking_lots[pid]["reserved"] > 0:
                        parking_lots[pid]["reserved"] -= 1
                reservations.clear()
                save_reservation_data(reservations)
                save_parking_lot_data(parking_lots)
                self.audit_logger.audit(session_user, action="delete_all_reservations_by_admin")
                self._send_json_response(200, "application/json", {"status": "All reservations deleted by admin"})
                return
            else:
                user_reservations_to_delete = [res_id for res_id, res in reservations.items() if res.get("user") == session_user["username"]]
                if not user_reservations_to_delete:
                    self._send_json_response(404, "application/json", {"error": "No reservations found for this user"})
                    return
                for res_id in user_reservations_to_delete:
                    reservation = reservations[res_id]
                    pid = reservation["parkinglot"]
                    if parking_lots[pid]["reserved"] > 0:
                        parking_lots[pid]["reserved"] -= 1
                    del reservations[res_id]
                save_reservation_data(reservations)
                save_parking_lot_data(parking_lots)
                self.audit_logger.audit(session_user, action="delete_all_user_reservations")
                self._send_json_response(200, "application/json", {"status": "All user reservations deleted"})
                return

        if rid not in reservations:
            self._send_json_response(404, "application/json", {"error": "Reservation not found"})
            return

        if not (session_user["role"] == "ADMIN") and not session_user["username"] == reservations[rid].get("user"):
            self._send_json_response(403, "application/json", {"error": "Access denied"})
            return

        reservation_to_delete = reservations[rid]
        pid = reservation_to_delete["parkinglot"]

        if parking_lots[pid]["reserved"] > 0:
            parking_lots[pid]["reserved"] -= 1
        else:
            self._send_json_response(400, "application/json", {"error": "Parking lot reserved count is already zero"})
            return

        del reservations[rid]
        save_reservation_data(reservations)
        save_parking_lot_data(parking_lots)
        self._send_json_response(200, "application/json", {"status": "Deleted"})

    @login_required
    def _handle_delete_vehicle(self, session_user):
        vid = self.path.replace("/vehicles/", "")
        
        vehicles = self._load_vehicles()
        user_vehicles = vehicles.get(session_user["username"])
        
        if not user_vehicles:
            self._send_json_response(404, "application/json", {"error": "User vehicles not found"})
            return
        
        original_len = len(user_vehicles)
        user_vehicles = [v for v in user_vehicles if v.get('id') != vid]
        
        if len(user_vehicles) == original_len:
            self._send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        vehicles[session_user["username"]] = user_vehicles
        save_data("vehicles.json", vehicles)
        self.audit_logger.audit(session_user, action="delete_vehicle", target=vid)
        self._send_json_response(200, "application/json", {"status": "Deleted"})

    def _handle_index(self):
        self._send_json_response(200, "text/html; charset=utf-8", 
            "<html><head><title>MobyPark API</title></head>"
            "<body>"
            "<h1>MobyPark API is running</h1>"
            "<p>Try endpoints like <code>/parking-lots</code>, <code>/profile</code> (requires Authorization), etc.</p>"
            "</body></html>"
        )

    def _handle_favicon(self):
        self._send_json_response(204, "image/x-icon", "")

    def _handle_get_parking_lots(self):
        parking_lots = load_parking_lot_data()
        self._send_json_response(200, "application/json", parking_lots)

    def _handle_get_parking_lot_details(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return

        self._send_json_response(200, "application/json", parking_lots[lid])

    @login_required 
    def _handle_get_parking_lot_sessions(self, session_user):
        parking_lots = load_parking_lot_data()
        lid = self.path.split("/")[-1]
        if not lid.isdigit():
            self._send_json_response(400,"application/json",{"error":"Invalid session id"}); return
        
        if lid not in parking_lots:
            self._send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        
        rsessions = []
        
        if self.path.endswith('/sessions'):
            if session_user["role"] == "ADMIN":
                rsessions = sessions
            else:
                for session in sessions.values():
                    if session.get('user') == session_user["username"]:
                        rsessions.append(session)
            self._send_json_response(200, "application/json", rsessions)
        else:
            sid = self.path.split("/")[-1]
            if not (session_user["role"] == "ADMIN") and not session_user["username"] == sessions[sid].get("user"):
                self._send_json_response(403, "application/json", {"error": "Access denied"})
                return
            self._send_json_response(200, "application/json", sessions[sid])

    @login_required
    def _handle_get_reservations(self, session_user):
        reservations = load_reservation_data()
        user_reservations = {rid: res for rid, res in reservations.items() if res.get("user") == session_user["username"] or session_user["role"] == "ADMIN"}
        self._send_json_response(200, "application/json", user_reservations)

    @login_required
    def _handle_get_reservation_details(self, session_user):
        reservations = load_reservation_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_json_response(404, "application/json", {"error": "Reservation not found"})
            return
                

        
        if not (session_user["role"] == "ADMIN") and not session_user["username"] == reservations[rid].get("user"):
            self._send_json_response(403, "application/json", {"error": "Access denied"})
            return
        
        self._send_json_response(200, "application/json", reservations[rid])

    @login_required
    def _handle_get_payments(self, session_user):
        payments = []
        for payment in load_payment_data():
            if payment.get("initiator") == session_user["username"] or payment.get("processed_by") == session_user["username"] or session_user["role"] == "ADMIN":
                payments.append(payment)
        self._send_json_response(200, "application/json", payments)

    @login_required
    def _handle_get_payment_details(self):
        session_user = authentication.get_user_from_session(self)
        pid = self.path.replace("/payments/", "")
        payments = load_payment_data()
        payment = next((p for p in payments if p.get("transaction") == pid), None)
        if not payment:
            self._send_json_response(404, "application/json", {"error": "Payment not found!"})
            return
        if not (session_user["role"] == "ADMIN") and payment.get("initiator") != session_user["username"]:
            self._send_json_response(403, "application/json", {"error": "Access denied"})
            return
        self._send_json_response(200, "application/json", payment)

    @login_required
    def _handle_get_billing(self, session_user):
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
        self._send_json_response(200, "application/json", data)

    def _load_vehicles(self):
        vehicles = load_json("vehicles.json")
        if isinstance(vehicles, dict):
            return vehicles
        return {}

    def _save_vehicles(self, vehicles):
        save_data("vehicles.json", vehicles)

    
    @roles_required(['ADMIN'])
    def _handle_get_user_billing(self, session_user):
        
        user = self.path.replace("/billing/", "")
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
        self.audit_logger.audit(session_user, action="get_user_billing", target=session_user["username"])
        self._send_json_response(200, "application/json", data)

    @login_required
    def _handle_get_vehicles(self, session_user):
        vehicles_data = self._load_vehicles()

        if session_user["role"] == "ADMIN":
            all_vehicles = []
            for user_v_list in vehicles_data.values():
                all_vehicles.extend(user_v_list)
            self._send_json_response(200, "application/json", all_vehicles)
            return
        else:
            user_vehicles = vehicles_data.get(session_user["username"], [])
            if not user_vehicles:
                self._send_json_response(404, "application/json", {"error": "No vehicles found for this user"})
                return
            self._send_json_response(200, "application/json", user_vehicles)

    @login_required
    def _handle_get_vehicle_reservations(self, session_user):
        vid = self.path.split("/")[2]
        
        target_user = session_user["username"]
        if self.path.count('/') > 3:
            parts = self.path.split('/')
            if parts[2] and parts[2] != vid:
                target_user = parts[2]
                vid = parts[3]
            else:
                self._send_json_response(400, "application/json", {"error": "Invalid vehicle reservations request"})
                return
        
        vehicles = self._load_vehicles()
        user_vehicles = vehicles.get(target_user)
        
        if not user_vehicles:
            self._send_json_response(404, "application/json", {"error": "User or vehicle not found"})
            return
            
        vehicle = next((v for v in user_vehicles if v.get('id') == vid), None)
        if not vehicle:
            self._send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
            
        reservations = load_reservation_data()
        vehicle_reservations = [res for res in reservations.values() if res.get('licenseplate') == vehicle['license_plate'] and res.get('user') == target_user]
        
        self._send_json_response(200, "application/json", vehicle_reservations)

    @login_required
    def _handle_get_vehicle_history(self, session_user):
        match = re.match(r"^/vehicles/([^/]+)/history$", self.path)
        if not match:
            self._send_json_response(400, "application/json", {"error": "Invalid URL format"})
            return
        license_plate = match.group(1)

        is_admin = session_user["role"] == "ADMIN"
        target_username = session_user["username"]

        vehicles_data = load_json("vehicles.json")
        reservations_data = load_json("reservations.json")
        sessions_data = load_json("sessions.json")

        vehicle = None
        vehicle_owner_username = None
        for user_vehicles in vehicles_data.values():
            for v_data in user_vehicles:
                if v_data.get("license_plate") == license_plate:
                    vehicle = v_data
                    vehicle_owner_username = v_data.get("user")
                    break
            if vehicle:
                break
        
        if not vehicle:
            self._send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return

        if not (session_user["role"] == "ADMIN") and target_username != vehicle_owner_username:
            self._send_json_response(403, "application/json", {"error": "Access denied. You can only view your own vehicle's history."})
            return

        history = []
        for res_data in reservations_data.values():
            if res_data.get("license_plate") == license_plate:
                history.append({"type": "reservation", "data": res_data})

        for sess_data in sessions_data.values():
            if sess_data.get("license_plate") == license_plate:
                history.append({"type": "session", "data": sess_data})
        
        history.sort(key=lambda x: x["data"].get("start_time", ""))

        self._send_json_response(200, "application/json", history)

    @login_required
    def _handle_get_vehicle_reservations_by_license_plate(self, session_user):
        match = re.match(r"^/vehicles/([^/]+)/reservations$", self.path)
        if not match:
            self._send_json_response(400, "application/json", {"error": "Invalid URL format"})
            return
        license_plate = match.group(1)

        is_admin = session_user["role"] == "ADMIN"
        target_username = session_user["username"]

        vehicles_data = load_json("vehicles.json")
        reservations_data = load_json("reservations.json")

        vehicle = None
        vehicle_owner_username = None
        for user_vehicles in vehicles_data.values():
            for v_data in user_vehicles:
                if v_data.get("license_plate") == license_plate:
                    vehicle = v_data
                    vehicle_owner_username = v_data.get("user")
                    break
            if vehicle:
                break
        
        if not vehicle:
            self._send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return

        if not (session_user["role"] == "ADMIN") and target_username != vehicle_owner_username:
            self._send_json_response(403, "application/json", {"error": "Access denied. You can only view your own vehicle's reservations."})
            return

        vehicle_reservations = [res for res in reservations_data.values() if res.get('license_plate') == license_plate and res.get('user') == vehicle_owner_username]
        
        self._send_json_response(200, "application/json", vehicle_reservations)

    @login_required
    def _handle_get_vehicle_details(self, session_user):
        
        match_id_only = re.match(r"^/vehicles/([^/]+)$", self.path)
        match_user_and_id = re.match(r"^/vehicles/([^/]+)/([^/]+)$", self.path)

        vid = None
        target_username = session_user["username"]

        if match_id_only:
            vid = match_id_only.group(1)
        elif match_user_and_id:
            if session_user["role"] == "ADMIN":
                target_username = match_user_and_id.group(1)
                vid = match_user_and_id.group(2)
            else:
                self._send_json_response(403, "application/json", {"error": "Access denied. Non-admin users cannot specify a username in the path."})
                return
        else:
            self._send_json_response(400, "application/json", {"error": "Invalid URL format for vehicle details"})
            return

        vehicles_data = self._load_vehicles()
        user_vehicles = vehicles_data.get(target_username, [])
        
        if not user_vehicles:
            self._send_json_response(404, "application/json", {"error": f"No vehicles found for user {target_username}"})
            return
        
        vehicle = next((v for v in user_vehicles if v.get('id') == vid), None)
        
        if not vehicle:
            self._send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        self._send_json_response(200, "application/json", {"status": "Accepted", "vehicle": vehicle})
   
    def _handle_debug_reset(self):
        pass

    def update_activity(self):
        self.last_activity = time.time()

    def session_expiry_maintenance(self):
        timer = threading.Timer(600, self.session_expiry_maintenance)
        timer.daemon = True
        timer.start()
        if time.time() - self.last_activity > self.timeout:
            authentication.handle_logout(self)

'''Deze aangepaste import functie zorgt voor het volgende:
De aanpassing in de https zorgt ervoor dat je meerdere request tegelijk kan afhandelen ipv 1
door de threadingmix in the combineren met de https server krijgt elke request zijn eigen thread
Dat zorgt er voor dat indien er een nieuw request is, die niet geblokt wordt terwijl er nog een andere bezig is

En daemon_threads = true zorgt er voor dat de threads automatisch stoppen zodra de server stopt'''
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

server = ThreadingHTTPServer(('localhost', 8000), RequestHandler)
print("Server running on http://localhost:8000")
server.serve_forever()