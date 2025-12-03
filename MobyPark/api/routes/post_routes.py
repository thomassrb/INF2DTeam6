import re
import uuid
import hashlib
import bcrypt
import os

from datetime import datetime
import session_manager

from authentication import login_required, roles_required
import session_calculator as sc
from app import access_vehicles, access_parkinglots, access_payments, access_reservations, access_sessions, access_users, connection
from MobyPark.api.Models.User import User
from MobyPark.api.Models.ParkingLot import ParkingLot
from MobyPark.api.Models.Reservation import Reservation
from MobyPark.api.Models.Vehicle import Vehicle
from MobyPark.api.Models.Payment import Payment
from MobyPark.api.Models.TransanctionData import TransactionData


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

        if access_users.get_user_byusername(username=username):
            handler.send_json_response(409, "application/json", {"error": "Username already taken"})
            return

        new_user = User(
            username = username,
            password = hashed_password,
            name = name,
            phone = phone_number,
            email = email,
            birth_year = birth_year,
            role = data.get('role', 'USER'),
            active = True,
            created_at = datetime.now().strftime("%Y-%m-%d")
        )
        access_users.add_user(user=new_user)
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

        user_to_authenticate = access_users.get_user_byusername(username=username)

        # COMMENTS TOEVOEGEN VOOR ONDERSTAAND STATEMENT
        if user_to_authenticate:
            if user_to_authenticate.password.startswith("$2b$"):
                if bcrypt.checkpw(password.encode('utf-8'), user_to_authenticate["password"].encode('utf-8')):
                    token = str(uuid.uuid4())
                    session_manager.add_session(token, user_to_authenticate)
                    handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                    return
            else:
                hashed_password_input = hashlib.sha256(password.encode('utf-8')).hexdigest()
                if hashed_password_input == user_to_authenticate.password:
                    token = str(uuid.uuid4())
                    session_manager.add_session(token, user_to_authenticate)
                    handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                    return

        handler.send_json_response(401, "application/json", {"error": "Invalid credentials"})


    def _handle_create_parking_lot(self):
            data = self.get_request_data()

            required_fields = ['name', 'location', 'capacity', 'tariff', 'daytariff', 'address', 'coordinates']
            for field in required_fields:
                if field not in data or not isinstance(data[field], str) or not data[field].strip():
                    self.send_json_response(400, "application/json", {"error": f"Missing or invalid field: {field}", "field": field})
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

            parking_lot = ParkingLot(
                name = data['name'],
                location = data['location'],
                capacity = data['capacity'],
                hourly_rate = data['tariff'],
                day_rate = data['daytariff'],
                address = data['address'],
                coordinates = data['coordinates'],
                reserved = 0
            )
            access_parkinglots.add_parking_lot(parkinglot=parking_lot)
            self.send_json_response(201, "application/json", {"Server message": f"Parking lot saved under ID: {parking_lot.id}"})


    @login_required
    def _handle_create_reservation(self, session_user: User):
        data = self.get_request_data()
        parking_lot = access_parkinglots.get_parking_lot(id=data['parkinglot'])
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        if not parking_lot:
            self.send_json_response(404, "application/json", {"error": "Parking lot not found", "field": "parkinglot"})
            return
        
        if not (session_user.role == "ADMIN"):
            if "user" not in data:
                data["user"] = session_user.username
            elif data["user"] != session_user.username:
                self.send_json_response(403, "application/json", {"error": "Non-admin users cannot create reservations for other users"})
                return
        else:
            if "user" not in data:
                data["user"] = None

        # toegevoegd, dit zorgt ervoor dat beide mogelijk zijn als data, hij replaced de var licenseplate dan met license_plate 
        if 'license_plate' not in data and 'licenseplate' in data:
            data['license_plate'] = data['licenseplate']

        vehicle = access_vehicles.get_vehicle_bylicenseplate(licenseplate=data['license_plate'])
        if not vehicle:
            self.send_json_response(404, "application/json", {"error": "Vehicle licenseplate not found"})
            return


        new_reservation = Reservation(
            user=session_user,
            parking_lot=parking_lot,
            vehicle=vehicle,
            start_time=data["start_time"],
            end_time=data["end_time"],
            status="confirmed",
            created_at=datetime.now(),
            cost=0.00
        )
        parking_lot.reserved += 1
        access_parkinglots.update_parking_lot(parkinglot=parking_lot)
        access_reservations.add_reservation(reservation=new_reservation)
        self.send_json_response(201, "application/json", {"status": "Success", "reservation": data})
    

    @login_required
    def _handle_create_vehicle(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        if access_vehicles.get_vehicle_bylicenseplate(licenseplate=data["licenseplate"]):
            self.send_json_response(409, "application/json", {"error": "Vehicle already exists"})
            return
        
        vehicle = Vehicle(
            user=session_user,
            license_plate=data['licenseplate'],
            make=data.get("make"),
            model=data.get("model"),
            color=data.get("color"),
            year=data.get("year"),
            created_at=datetime.now().strftime("%Y-%m-%d")
        )
        access_vehicles.add_vehicle(vehicle=vehicle)
        self.audit_logger.audit(session_user, action="create_vehicle", target=vehicle.id, extra={"license_plate": data['licenseplate']})
        self.send_json_response(201, "application/json", {"status": "Success", "vehicle": vehicle})


    @login_required
    def _handle_create_payment(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        payment = Payment(
            transaction=data['transaction'],
            amount=data['amount'],
            initiator=session_user,
            created_at=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            completed=None,
            session=access_sessions.get_session(id=data["session"]),
            parking_lot=access_parkinglots.get_parking_lot(id=data["parking_lot"]),
            t_data=TransactionData(**data["t_data"]),
            hash=sc.generate_transaction_validation_hash()
        )
        access_payments.add_payment(payment=payment)
        self.audit_logger.audit(session_user, action="create_payment", target=payment.transaction, extra={"amount": payment["amount"], "coupled_to": payment.get("coupled_to")})
        self.send_json_response(201, "application/json", {"status": "Success", "payment": payment})

# hier gebleven -----------------------------------------------------------------------------------------------------
    @login_required
    def _handle_start_session(self, session_user):
        match = re.match(r"^/parking-lots/([^/]+)/sessions/start$", self.path)
        if not match:
            self.send_json_response(400, "application/json", {"error": "Invalid URL format for starting session"})
            return
        lid = match.group(1)
        data = self.get_request_data()

        lp = data.get('license_plate') or data.get('licenseplate')
        if not isinstance(lp, str) or not lp.strip():
            self.send_json_response(400, "application/json", {"error": "Missing or invalid field: license_plate", "field": "license_plate"})
            return

        sessions = load_json(f'pdata/p{lid}-sessions.json')
        filtered = {key: value for key, value in sessions.items() if (value.get("license_plate") == lp or value.get("licenseplate") == lp) and not value.get('stopped')}

        if len(filtered) > 0:
            self.send_json_response(409, "application/json", {"error": "Cannot start a session when another session for this license plate is already started."})
            return 

        session = {
            "license_plate": lp,
            "started": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            "stopped": None,
            "user": session_user["username"]
        }
        sessions[str(len(sessions) + 1)] = session
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self.send_json_response(200, "application/json", {"Server message": f"Session started for: {lp}"})

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
        filtered = {key: value for key, value in sessions.items() if (value.get("license_plate") == lp or value.get("licenseplate") == lp) and not value.get('stopped')}
        
        if len(filtered) == 0:
            self.send_json_response(409, "application/json", {"error": "Cannot stop a session when there is no session for this license plate."})
            return
        
        sid = next(iter(filtered))
        sessions[sid]["stopped"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        save_data(f'pdata/p{lid}-sessions.json', sessions)
        self.audit_logger.audit(session_user, action="stop_session", target=sid, extra={"license_plate": lp, "parking_lot": lid})
        self.send_json_response(200, "application/json", {"Server message": f"Session stopped for: {lp}"})

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