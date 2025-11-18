import re
import uuid
import hashlib
import bcrypt
import os

from datetime import datetime
import session_manager
import authentication


from storage_utils import load_json, load_payment_data, load_reservation_data, save_data, save_payment_data, save_reservation_data, save_user_data, load_parking_lot_data, save_parking_lot_data, load_json, save_user_data, load_vehicles_data, save_vehicles_data
from authentication import login_required, roles_required
import session_calculator as sc


class post_routes:
    def handle_register(handler):
        data = handler.get_request_data()

        required_fields = ['username', 'password', 'name', 'phone', 'email', 'birth_year']
        for field in required_fields:
            if field not in data or not isinstance(data[field], str) or not data[field].strip():
                handler.send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
                return

        username = data['username']
        password = data['password']
        name = data['name']
        phone_number = data['phone']
        email = data['email']
        birth_year = data['birth_year']

        TEST_MODE = os.environ.get('TEST_MODE') == '1'
        if TEST_MODE:
            # In tests, store fast SHA256 to minimize hashing cost
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        else:
            rounds = None
            salt = bcrypt.gensalt(rounds=rounds) if rounds else bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        users = load_json('users.json')

        if any(user['username'] == username for user in users):
            handler.send_json_response(409, "application/json", {"error": "Username already taken"})
            return

        new_id = str(max(int(u.get("id", 0)) for u in users) + 1) if users else "1"
        new_user = {
            'id': new_id,
            'username': username,
            'password': hashed_password,
            'name': name,
            'phone': phone_number,
            'email': email,
            'birth_year': birth_year,
            'role': data.get('role', 'USER'),
            'active': True,
            'created_at': datetime.now().strftime("%Y-%m-%d")
        }
        users.append(new_user)
        save_user_data(users)
        handler.send_json_response(201, "application/json", {"message": "User created"})

    def handle_login(handler):
        data = handler.get_request_data()

        required_fields = ['username', 'password']
        for field in required_fields:
            if field not in data or not isinstance(data[field], str) or not data[field].strip():
                handler.send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
                return

        username = data['username']
        password = data['password']

        users = load_json('users.json')
        user_to_authenticate = None
        DEBUG_LOGS = os.environ.get('DEBUG_LOGS') == '1'
        if DEBUG_LOGS:
            print(f"DEBUG: Searching for user '{username}' in users list of type {type(users)}")
        for u in users:
            if DEBUG_LOGS:
                print(f"DEBUG: Checking user: {u.get('username')}")
            if u.get("username") == username:
                user_to_authenticate = u
                if DEBUG_LOGS:
                    print(f"DEBUG: Found user {username}: {user_to_authenticate}")
                break

        # COMMENTS TOEVOEGEN VOOR ONDERSTAAND STATEMENT
        if user_to_authenticate:
            if user_to_authenticate.get("password", "").startswith("$2b$"):
                if bcrypt.checkpw(password.encode('utf-8'), user_to_authenticate["password"].encode('utf-8')):
                    if DEBUG_LOGS:
                        print(f"DEBUG: Bcrypt match for user {username}")
                    token = str(uuid.uuid4())
                    session_manager.add_session(token, user_to_authenticate)
                    handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                    return
            else:
                hashed_password_input = hashlib.sha256(password.encode('utf-8')).hexdigest()
                if hashed_password_input == user_to_authenticate.get("password", ""):
                    if DEBUG_LOGS:
                        print(f"DEBUG: SHA256 match for user {username}")
                    token = str(uuid.uuid4())
                    session_manager.add_session(token, user_to_authenticate)
                    handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                    return

        if DEBUG_LOGS:
            print(f"DEBUG: Login failed for username: {username}. Provided password: {password}. Stored user: {user_to_authenticate}")
        handler.send_json_response(401, "application/json", {"error": "Invalid credentials"})

    def _handle_create_parking_lot(self):
        data = self.get_request_data()


        required_fields = ['name', 'location', 'capacity', 'tariff', 'daytariff', 'address', 'coordinates']
        for field in required_fields:
            if field not in data:
                self.send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
                return


        for sf in ['name', 'location', 'address']:
            if not isinstance(data.get(sf), str) or not data.get(sf, '').strip():
                self.send_json_response(400, "application/json", {"error": f"Missing or invalid field: {sf}", "field": sf})
                return


        if not isinstance(data['capacity'], int) or data['capacity'] <= 0:
            self.send_json_response(400, "application/json", {"error": "Capacity must be a positive integer", "field": "capacity"})
            return
        if not isinstance(data['tariff'], (int, float)) or data['tariff'] < 0:
            self.send_json_response(400, "application/json", {"error": "Tariff must be a non-negative number", "field": "tariff"})
            return
        if not isinstance(data['daytariff'], (int, float)) or data['daytariff'] < 0:
            self.send_json_response(400, "application/json", {"error": "Day tariff must be a non-negative number", "field": "daytariff"})
            return
        if not isinstance(data['coordinates'], list) or not all(isinstance(coord, (int, float)) for coord in data['coordinates']) or len(data['coordinates']) != 2:
            self.send_json_response(400, "application/json", {"error": "Coordinates must be a list of two numbers", "field": "coordinates"})
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
        self.send_json_response(201, "application/json", {"message": f"Parking lot saved under ID: {new_lid}"})

    @login_required
    def _handle_create_reservation(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        reservations = load_reservation_data()
        parking_lots = load_parking_lot_data()
        
        if data['parkinglot'] not in parking_lots:
            self.send_json_response(404, "application/json", {"error": "Parking lot not found", "field": "parkinglot"})
            return
        
        if not (session_user["role"] == "ADMIN"):
            if "user" not in data:
                data["user"] = session_user["username"]
            elif data["user"] != session_user["username"]:
                self.send_json_response(403, "application/json", {"error": "Non-admin users cannot create reservations for other users"})
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
        self.send_json_response(201, "application/json", {"status": "Success", "reservation": data})
    
    @login_required
    def _handle_create_vehicle(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        vehicles = load_vehicles_data()
        users = load_json('users.json')
        current_user = next((u for u in users if u.get('username') == session_user['username']), None)
        
        if not current_user:
            self.send_json_response(404, "application/json", {"error": "User not found"})
            return
        
        user_vehicles = vehicles.get(current_user["username"], [])
        if any(v for v in user_vehicles if v.get('license_plate') == data['licenseplate']):
            self.send_json_response(409, "application/json", {"error": "Vehicle already exists for this user"})
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
        save_vehicles_data(vehicles)
        self.audit_logger.audit(session_user, action="create_vehicle", target=new_vid, extra={"license_plate": data['licenseplate']})
        self.send_json_response(201, "application/json", {"status": "Success", "vehicle": vehicle})

    @login_required
    def _handle_create_payment(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
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
        self.send_json_response(201, "application/json", {"status": "Success", "payment": payment})

    @login_required
    def _handle_start_session(self, session_user):
        session_user = authentication.get_user_from_session(self)
        if not session_user:
            self.send_json_response(401, "application/json", {"error": "Unauthorized"})
            return
        match = re.match(r"^/parking-lots/([^/]+)/sessions/start$", self.path)
        if not match:
            self.send_json_response(400, "application/json", {"error": "Invalid URL format for starting session"})
            return
        lid = match.group(1)
        data = self.get_request_data()

        lp = data.get('license_plate') or data.get('licenseplate')
        if not isinstance(lp, str) or not lp.strip():
            self.send_json_response(400, "application/json", {"error": "Missing or invalid field: licenseplate", "field": "licenseplate"})
            return

        sessions = load_json(f'pdata/p{lid}-sessions.json')
        filtered = {key: value for key, value in sessions.items() if (value.get("licenseplate") == lp or value.get("license_plate") == lp) and not value.get('stopped')}


        if len(filtered) > 0:
            self.send_json_response(409, "application/json", {"error": "Cannot start a session when another session for this license plate is already started."})
            return 

        session = {
            "licenseplate": lp,
            "license_plate": lp,
            "started": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            "stopped": None,
            "user": session_user["username"]
        }
        sessions[str(len(sessions) + 1)] = session
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self.send_json_response(200, "application/json", {"message": f"Session started for: {lp}"})


    @login_required
    def _handle_stop_session(self, session_user):
        match = re.match(r"^/parking-lots/([^/]+)/sessions/stop$", self.path)
        if not match:
            self.send_json_response(400, "application/json", {"error": "Invalid URL format for stopping session"})
            return
        lid = match.group(1)
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        sessions = load_json(f'pdata/p{lid}-sessions.json')
        lp = data.get('license_plate') or data.get('licenseplate')
        filtered = {key: value for key, value in sessions.items() if (value.get("licenseplate") == lp or value.get("license_plate") == lp) and not value.get('stopped')}
        
        if len(filtered) == 0:
            self.send_json_response(409, "application/json", {"error": "Cannot stop a session when there is no session for this license plate."})
            return
        
        sid = next(iter(filtered))
        sessions[sid]["stopped"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self.audit_logger.audit(session_user, action="stop_session", target=sid, extra={"licenseplate": lp, "parking_lot": lid})
        self.send_json_response(200, "application/json", {"message": f"Session stopped for: {lp}"})


    @roles_required(['ADMIN'])
    def _handle_refund_payment(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
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
        self.send_json_response(201, "application/json", {"status": "Success", "payment": payment})
 

    @roles_required(['ADMIN'])
    def _handle_debug_reset(self, session_user):
        # Cleared de users data
        save_user_data([])
        # Cleared parking lots data
        save_parking_lot_data({})
        # Cleared reserveringen data
        save_reservation_data({})
        # Cleared payment data
        save_payment_data([])
        # Cleared de voertuigen data
        self._save_vehicles({})
        # Cleared de huidige sessions
        self.session_manager.active_sessions.clear()

        self.audit_logger.audit(session_user, action="debug_reset", target="all_data")
        self.send_json_response(200, "application/json", {"Server message": "All data reset successfully"})