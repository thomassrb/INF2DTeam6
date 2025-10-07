import json
import hashlib
import uuid
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from storage_utils import load_json, save_data, save_user_data, load_parking_lot_data, save_parking_lot_data, save_reservation_data, load_reservation_data, load_payment_data, save_payment_data
from session_manager import add_session, get_session
import session_calculator as sc

class RequestHandler(BaseHTTPRequestHandler):
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
                '/': self._handle_index,
                '/index': self._handle_index,
                '/index.html': self._handle_index,
                '/favicon.ico': self._handle_favicon,
                '/parking-lots': self._handle_get_parking_lots,
                '/profile': self._handle_get_profile,
                '/logout': self._handle_logout,
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
        self.end_headers()
        if isinstance(data, dict) or isinstance(data, list):
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
        else:
            self.wfile.write(str(data).encode('utf-8'))

    def _get_request_data(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return json.loads(self.rfile.read(content_length))
        return {}

    def do_POST(self):
        self._dispatch_request('POST')

    def do_PUT(self):
        self._dispatch_request('PUT')

    def do_DELETE(self):
        self._dispatch_request('DELETE')

    def do_GET(self):
        self._dispatch_request('GET')

    def _dispatch_request(self, method):
        for path_prefix, handler in self.routes[method].items():
            if len(path_prefix) > 1 and self.path.startswith(path_prefix) and path_prefix.endswith('/'):
                handler()
                return
            elif self.path == path_prefix and not path_prefix.endswith('/'):
                handler()
                return
        self._send_response(404, "application/json", {"error": "Not Found"})

    def _validate_data(self, data, required_fields=None, optional_fields=None):
        if required_fields is None: required_fields = {}
        if optional_fields is None: optional_fields = {}

        for field, expected_type in required_fields.items():
            if field not in data:
                return False, {"error": "Required field missing", "field": field}
            if not isinstance(data[field], expected_type):
                return False, {"error": f"Invalid type for field {field}", "expected_type": str(expected_type), "received_type": str(type(data[field]))}

        for field, expected_type in optional_fields.items():
            if field in data and not isinstance(data[field], expected_type):
                return False, {"error": f"Invalid type for field {field}", "expected_type": str(expected_type), "received_type": str(type(data[field]))}
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
        
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        users = load_json('data/users.json')
        
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
        
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        users = load_json('data/users.json')
        
        user = next((u for u in users if u.get("username") == username and u.get("password") == hashed_password), None)
        if user:
            token = str(uuid.uuid4())
            add_session(token, user)
            self._send_response(200, "application/json", {"message": "User logged in", "session_token": token})
        else:
            self._send_response(401, "application/json", {"error": "Invalid credentials"})

    def _handle_create_parking_lot(self):
        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user): return
        
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
        self._send_response(201, "application/json", {"message": f"Parking lot saved under ID: {new_lid}"})

    def _handle_start_session(self):
        session_user = self._authenticate()
        if not session_user: return
        
        lid = self.path.split("/")[2]
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        sessions = load_json(f'data/pdata/p{lid}-sessions.json')
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
        save_data(f'data/pdata/p{lid}-sessions.json', sessions)
        self._send_response(200, "application/json", {"message": f"Session started for: {data['licenseplate']}"})

    def _handle_stop_session(self):
        session_user = self._authenticate()
        if not session_user: return
        
        lid = self.path.split("/")[2]
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        sessions = load_json(f'data/pdata/p{lid}-sessions.json')
        filtered = {key: value for key, value in sessions.items() if value.get("licenseplate") == data['licenseplate'] and not value.get('stopped')}
        
        if len(filtered) == 0:
            self._send_response(409, "application/json", {"error": "Cannot stop a session when there is no session for this license plate."})
            return
        
        sid = next(iter(filtered))
        sessions[sid]["stopped"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        save_data(f'data/pdata/p{lid}-sessions.json', sessions)
        self._send_response(200, "application/json", {"message": f"Session stopped for: {data['licenseplate']}"})

    def _handle_create_reservation(self):
        session_user = self._authenticate()
        if not session_user: return
        
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
            else:
                data["user"] = session_user["username"]
        else:
            data["user"] = session_user["username"]
        
        rid = str(len(reservations) + 1)
        reservations[rid] = data
        data["id"] = rid
        parking_lots[data["parkinglot"]]["reserved"] += 1
        save_reservation_data(reservations)
        save_parking_lot_data(parking_lots)
        self._send_response(201, "application/json", {"status": "Success", "reservation": data})

    def _handle_create_vehicle(self):
        session_user = self._authenticate()
        if not session_user: return
        
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'licenseplate': str},
            optional_fields={'name': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        vehicles = load_json("data/vehicles.json")
        users = load_json('data/users.json')
        current_user = next((u for u in users if u.get('username') == session_user['username']), None)
        
        if not current_user:
            self._send_response(404, "application/json", {"error": "User not found"})
            return
        
        user_vehicles = vehicles.get(current_user["username"], [])
        if any(v for v in user_vehicles if v.get('licenseplate') == data['licenseplate']):
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
        save_data("data/vehicles.json", vehicles)
        self._send_response(201, "application/json", {"status": "Success", "vehicle": vehicle})

    def _handle_create_payment(self):
        session_user = self._authenticate()
        if not session_user: return
        
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
        self._send_response(201, "application/json", {"status": "Success", "payment": payment})

    def _handle_refund_payment(self):
        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user): return
        
        data = self._get_request_data()
        
        valid, error = self._validate_data(data,\
            required_fields={'amount': (int, float)},\
            optional_fields={'transaction': str, 'coupled_to': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        payments = load_payment_data() # Define payments here before using it
        payment = {
            "transaction": data.get("transaction") if data.get("transaction") else sc.generate_payment_hash(session_user["username"], str(datetime.now())),
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

    def _handle_update_profile(self):
        session_user = self._authenticate()
        if not session_user: return
        
        data = self._get_request_data()
        
        valid, error = self._validate_data(data,\
            optional_fields={'name': str, 'password': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return

        data["username"] = session_user["username"]
        if data.get("password"):
            data["password"] = hashlib.md5(data["password"].encode()).hexdigest()
        save_user_data(data)
        self._send_response(200, "application/json", {"message": "User updated successfully"})

    def _handle_update_parking_lot(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return
    
        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user): return
        
        data = self._get_request_data()
        
        valid, error = self._validate_data(data, 
            required_fields={'name': str, 'location': str, 'capacity': int, 'hourly_rate': (int, float), 'day_rate': (int, float)},
            optional_fields={'reserved': int}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        parking_lots[lid] = data
        save_parking_lot_data(parking_lots)
        self._send_response(200, "application/json", {"message": "Parking lot modified"})

    def _handle_update_reservation(self):
        data = self._get_request_data()
        reservations = load_reservation_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_response(404, "application/json", {"error": "Reservation not found"})
            return
        
        session_user = self._authenticate()
        if not session_user: return
        
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

    def _handle_update_vehicle(self):
        session_user = self._authenticate()
        if not session_user: return
        
        data = self._get_request_data()
        
        valid, error = self._validate_data(data,\
            required_fields={'name': str}\
        )
        if not valid:
            self._send_response(400, "application/json", error)
            return
        
        vehicles = load_json("data/vehicles.json")
        
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
        save_data("data/vehicles.json", vehicles)
        self._send_response(200, "application/json", {"status": "Success", "vehicle": next(v for v in user_vehicles if v.get('id') == vid)})

    def _handle_update_payment(self):
        session_user = self._authenticate()
        if not session_user: return
        
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

    def _handle_delete_parking_lot(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return

        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user): return
        
        del parking_lots[lid]
        save_parking_lot_data(parking_lots)
        self._send_response(200, "application/json", {"message": "Parking lot deleted"})

    def _handle_delete_session(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return
        
        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user): return
        
        sessions = load_json(f'data/pdata/p{lid}-sessions.json')
        sid = self.path.split("/")[-1]
        
        if not sid.isnumeric():
            self._send_response(400, "application/json", {"error": "Session ID is required, cannot delete all sessions"})
            return
                
        if sid not in sessions:
            self._send_response(404, "application/json", {"error": "Session not found"})
            return
        
        del sessions[sid]
        save_data(f'data/pdata/p{lid}-sessions.json', sessions)
        self._send_response(200, "application/json", {"message": "Session deleted"})

    def _handle_delete_reservation(self):
        reservations = load_reservation_data()
        parking_lots = load_parking_lot_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_response(404, "application/json", {"error": "Reservation not found"})
            return
        
        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user) and not session_user["username"] == reservations[rid].get("user"):
            self._send_response(403, "application/json", {"error": "Access denied"})
            return
        
        pid = reservations[rid]["parkinglot"]
        del reservations[rid]
        parking_lots[pid]["reserved"] -= 1
        save_reservation_data(reservations)
        save_parking_lot_data(parking_lots)
        self._send_response(200, "application/json", {"status": "Deleted"})

    def _handle_delete_vehicle(self):
        vid = self.path.replace("/vehicles/", "")
        
        session_user = self._authenticate()
        if not session_user: return
        
        vehicles = load_json("data/vehicles.json")
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
        save_data("data/vehicles.json", vehicles)
        self._send_response(200, "application/json", {"status": "Deleted"})

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

    def _handle_get_profile(self):
        session_user = self._authenticate()
        if not session_user: return
        
        # Filter out sensitive information
        profile_data = {k: v for k, v in session_user.items() if k != "password"}
        self._send_response(200, "application/json", profile_data)

    def _handle_logout(self):
        token = self.headers.get('Authorization')
        if token and get_session(token):
            # remove_session(token) # This line was removed from imports, so it\'s removed here.
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

    def _handle_get_parking_lot_sessions(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_response(404, "application/json", {"error": "Parking lot not found"})
            return
        
        session_user = self._authenticate()
        if not session_user: return
        
        sessions = load_json(f'data/pdata/p{lid}-sessions.json')
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

    def _handle_get_reservations(self):
        session_user = self._authenticate()
        if not session_user: return
        
        reservations = load_reservation_data()
        user_reservations = {rid: res for rid, res in reservations.items() if res.get("user") == session_user["username"] or session_user.get("role") == "ADMIN"}
        self._send_response(200, "application/json", user_reservations)

    def _handle_get_reservation_details(self):
        reservations = load_reservation_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self._send_response(404, "application/json", {"error": "Reservation not found"})
            return
                
        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user) and not session_user["username"] == reservations[rid].get("user"):
            self._send_response(403, "application/json", {"error": "Access denied"})
            return
        
        self._send_response(200, "application/json", reservations[rid])

    def _handle_get_payments(self):
        session_user = self._authenticate()
        if not session_user: return
        
        payments = []
        for payment in load_payment_data():
            if payment.get("initiator") == session_user["username"] or payment.get("processed_by") == session_user["username"] or session_user.get("role") == "ADMIN":
                payments.append(payment)
        self._send_response(200, "application/json", payments)

    def _handle_get_payment_details(self):
        session_user = self._authenticate()
        if not session_user: return
        
        pid = self.path.replace("/payments/", "")
        payments = load_payment_data()
        
        payment = next((p for p in payments if p["initiator"] == pid), None)
        
        if not payment:
            self._send_response(404, "application/json", {"error": "Payment not found!"})
            return
        
        if not self._authorize_admin(session_user) and not payment.get("initiator") == session_user["username"]:
            self._send_response(403, "application/json", {"error": "Access denied"})
            return

        self._send_response(200, "application/json", payment)

    def _handle_get_billing(self):
        session_user = self._authenticate()
        if not session_user: return
        
        data = []
        for pid, parkinglot in load_parking_lot_data().items():
            try:
                sessions = load_json(f'data/pdata/p{pid}-sessions.json')
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

    def _authenticate(self):
        token = self.headers.get('Authorization')
        if not token:
            self._send_response(401, "application/json", {"error": "Unauthorized: Missing session token"})
            return None
        session_user = get_session(token)
        if not session_user:
            self._send_response(401, "application/json", {"error": "Unauthorized: Invalid session token"})
            return None
        return session_user

    def _authorize_admin(self, session_user):
        if not session_user.get('role') == 'ADMIN':
            self._send_response(403, "application/json", {"error": "Access denied"})
            return False
        return True

    def _handle_get_user_billing(self):
        session_user = self._authenticate()
        if not session_user: return
        
        if not self._authorize_admin(session_user): return
        
        user = self.path.replace("/billing/", "")
        data = []
        for pid, parkinglot in load_parking_lot_data().items():
            try:
                sessions = load_json(f'data/pdata/p{pid}-sessions.json')
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

    def _handle_get_vehicles(self):
        session_user = self._authenticate()
        if not session_user: return
        
        vehicles = load_json("data/vehicles.json")
        
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.startswith("/vehicles/"):
            parts = self.path.split('/')
            if len(parts) > 2 and parts[2]:
                target_user = parts[2]
            else:
                # If admin accesses /vehicles without a specific user, return all vehicles (optional, based on desired behavior)
                all_vehicles = []
                for user_v_list in vehicles.values():
                    all_vehicles.extend(user_v_list)
                self._send_response(200, "application/json", all_vehicles)
                return
        
        if target_user not in vehicles:
            self._send_response(404, "application/json", {"error": "User or their vehicles not found"})
            return
        
        self._send_response(200, "application/json", vehicles.get(target_user, {}))

    def _handle_get_vehicle_reservations(self):
        session_user = self._authenticate()
        if not session_user: return
        
        vid = self.path.split("/")[2]
        
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.count('/') > 3:
            parts = self.path.split('/')
            if parts[2] and parts[2] != vid: # Admin requesting for specific user's vehicle reservations
                target_user = parts[2]
                vid = parts[3] # Expecting /vehicles/{user}/{vid}/reservations
            else:
                self._send_response(400, "application/json", {"error": "Invalid vehicle reservations request"})
                return
        
        vehicles = load_json("data/vehicles.json")
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

    def _handle_get_vehicle_history(self):
        session_user = self._authenticate()
        if not session_user: return
        
        vid = self.path.split("/")[2]
        
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.count('/') > 2:
            parts = self.path.split('/')
            if parts[2] and parts[2] != vid: # Admin requesting for a specific user's vehicle history
                target_user = parts[2]
                vid = parts[3] # Expecting /vehicles/{user}/{vid}/history
            elif parts[2] and parts[2] == vid: # Admin requesting own vehicle history but path might be /vehicles/{vid}
                pass # Use session_user, vid is already correctly parsed
            else:
                self._send_response(400, "application/json", {"error": "Invalid vehicle history request"})
                return
        
        vehicles = load_json("data/vehicles.json")
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
                sessions = load_json(f'data/pdata/p{pid}-sessions.json')
                for _, session in sessions.items():
                    if session.get('licenseplate') == vehicle['license_plate'] and session.get('user') == target_user:
                        all_sessions.append(session)
            except FileNotFoundError:
                continue # No sessions for this parking lot
        
        self._send_response(200, "application/json", all_sessions)

    def _handle_get_vehicle_details(self):
        session_user = self._authenticate()
        if not session_user: return
        
        vid = self.path.replace("/vehicles/", "").replace("/entry", "")
        vehicles = load_json("data/vehicles.json")
        
        target_user = session_user["username"]
        if self._authorize_admin(session_user) and self.path.count('/') > 2:
            parts = self.path.split('/')
            if parts[2] and parts[2] != vid: # Admin requesting details for a specific user's vehicle
                target_user = parts[2]
                vid = parts[3] if len(parts) > 3 else vid # If /vehicles/{user}/{vid}
            elif parts[2] and parts[2] == vid: # Admin requesting own vehicle details but path might be /vehicles/{vid}
                pass # Use session_user, vid is already correctly parsed
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