import re
from storage_utils import load_json, load_parking_lot_data, load_reservation_data, load_payment_data, load_vehicles_data
from authentication import extract_bearer_token, login_required, roles_required
import session_calculator as sc
import authentication


class get_routes:
    def handle_get_profile(handler, session_user):
        profile_data = {
        "username": session_user["username"],
        "role": session_user["role"],
        "name": session_user["name"],
        "email": session_user["email"],
        "phone": session_user["phone"],
        "birth_year": session_user.get("birth_year"),
        "created_at": session_user.get("created_at")
            }

        handler.send_json_response(200, "application/json", profile_data)

    def handle_get_profile_by_id(handler, session_user):
        match = re.match(r"^/profile/([^/]+)$", handler.path)
        if not match:
            handler.send_json_response(400, "application/json", {"error": "Invalid URL format"})
            return
        
        target_user_id = match.group(1)
        
        users = load_json('users.json')
        target_user = next((u for u in users if u.get("id") == target_user_id), None)
        
        if not target_user:
            handler.send_json_response(404, "application/json", {"error": "User not found"})
            return
        
        is_admin = session_user["role"] == "ADMIN"
        
        if not is_admin and session_user.get("id") != target_user_id:
            handler.send_json_response(403, "application/json", {"error": "Access denied. You can only view your own profile."})
            return
        
        profile_data = {
            "id": target_user.get("id"),
            "username": target_user.get("username"),
            "role": target_user.get("role"),
            "name": target_user.get("name"),
            "email": target_user.get("email"),
            "phone": target_user.get("phone"),
            "birth_year": target_user.get("birth_year"),
            "created_at": target_user.get("created_at")
        }
        
        handler.send_json_response(200, "application/json", profile_data)

    def handle_logout(handler):
        token = extract_bearer_token(handler.headers)
        if token and handler.session_manager.get_session(token):
            handler.session_manager.clear_sessions(token)
            handler.send_json_response(200, "application/json", {"message": "User logged out successfully"})
        else:
            handler.send_json_response(400, "application/json", {"error": "No active session or invalid token"})

    def _handle_index(self):
        self.send_json_response(200, "text/html; charset=utf-8", 
            "<html><head><title>MobyPark API</title></head>"
            "<body>"
            "<h1>MobyPark API is running</h1>"
            "<p>Try endpoints like <code>/parking-lots</code>, <code>/profile</code> (requires Authorization), etc.</p>"
            "</body></html>"
        )
    def _handle_favicon(self):
        self.send_json_response(204, "image/x-icon", "")

    def _handle_get_parking_lots(self):
        parking_lots = load_parking_lot_data()
        self.send_json_response(200, "application/json", parking_lots)
    
    @login_required
    def _handle_get_reservations(self, session_user):
        reservations = load_reservation_data()
        print(f"DEBUG: In _handle_get_reservations. Session User: {session_user}")
        print(f"DEBUG: Raw Reservations Data: {reservations}")
        user_reservations = {rid: res for rid, res in reservations.items() if res.get("user") == session_user["username"] or session_user["role"] == "ADMIN"}
        self.send_json_response(200, "application/json", user_reservations)

    @login_required
    def _handle_get_payments(self, session_user):
        payments = []
        for payment in load_payment_data():
            if payment.get("initiator") == session_user["username"] or payment.get("processed_by") == session_user["username"] or session_user["role"] == "ADMIN":
                payments.append(payment)
        self.send_json_response(200, "application/json", payments)
    
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
        self.send_json_response(200, "application/json", data)
    
    @login_required
    def _handle_get_vehicles(self, session_user):
        vehicles_data = load_vehicles_data()

        if session_user["role"] == "ADMIN":
            all_vehicles = []
            for user_v_list in vehicles_data.values():
                all_vehicles.extend(user_v_list)
            self.send_json_response(200, "application/json", all_vehicles)
            return
        else:
            user_vehicles = vehicles_data.get(session_user["username"], [])
            if not user_vehicles:
                self.send_json_response(404, "application/json", {"error": "No vehicles found for this user"})
                return
            self.send_json_response(200, "application/json", user_vehicles)
    
    def _handle_get_parking_lot_details(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self.send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return

        self.send_json_response(200, "application/json", parking_lots[lid])
    
    @login_required
    def _handle_get_reservation_details(self, session_user):
        reservations = load_reservation_data()
        rid = self.path.replace("/reservations/", "")
        
        if rid not in reservations:
            self.send_json_response(404, "application/json", {"error": "Reservation not found"})
            return
        
        if not (session_user["role"] == "ADMIN") and not session_user["username"] == reservations[rid].get("user"):
            self.send_json_response(403, "application/json", {"error": "Access denied"})
            return
        
        self.send_json_response(200, "application/json", reservations[rid])

    @login_required
    def _handle_get_payment_details(self):
        session_user = authentication.get_user_from_session(self)
        pid = self.path.replace("/payments/", "")
        payments = load_payment_data()
        payment = next((p for p in payments if p.get("transaction") == pid), None)
        if not payment:
            self.send_json_response(404, "application/json", {"error": "Payment not found!"})
            return
        if not (session_user["role"] == "ADMIN") and payment.get("initiator") != session_user["username"]:
            self.send_json_response(403, "application/json", {"error": "Access denied"})
            return
        self.send_json_response(200, "application/json", payment)

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
        self.send_json_response(200, "application/json", data)

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
                self.send_json_response(403, "application/json", {"error": "Access denied. Non-admin users cannot specify a username in the path."})
                return
        else:
            self.send_json_response(400, "application/json", {"error": "Invalid URL format for vehicle details"})
            return

        vehicles_data = load_vehicles_data()
        user_vehicles = vehicles_data.get(target_username, [])
        
        if not user_vehicles:
            self.send_json_response(404, "application/json", {"error": f"No vehicles found for user {target_username}"})
            return
        
        vehicle = next((v for v in user_vehicles if v.get('id') == vid), None)
        
        if not vehicle:
            self.send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        self.send_json_response(200, "application/json", {"status": "Accepted", "vehicle": vehicle})


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
                self.send_json_response(400, "application/json", {"error": "Invalid vehicle reservations request"})
                return

        vehicles = load_vehicles_data()
        user_vehicles = vehicles.get(target_user)
        
        if not user_vehicles:
            self.send_json_response(404, "application/json", {"error": "User or vehicle not found"})
            return
            
        vehicle = next((v for v in user_vehicles if v.get('id') == vid), None)
        if not vehicle:
            self.send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
            
        reservations = load_reservation_data()
        vehicle_reservations = [
            res for res in reservations.values()
            if (res.get('license_plate') == vehicle['license_plate'] or res.get('licenseplate') == vehicle['license_plate'])
            and res.get('user') == target_user
        ]
        
        self.send_json_response(200, "application/json", vehicle_reservations)

    @login_required
    def _handle_get_vehicle_history(self, session_user):
        match = re.match(r"^/vehicles/([^/]+)/history$", self.path)
        if not match:
            self.send_json_response(400, "application/json", {"error": "Invalid URL format"})
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
            self.send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return

        if not (session_user["role"] == "ADMIN") and target_username != vehicle_owner_username:
            self.send_json_response(403, "application/json", {"error": "Access denied. You can only view your own vehicle's history."})
            return

        history = []
        for res_data in reservations_data.values():
            if res_data.get("license_plate") == license_plate or res_data.get("licenseplate") == license_plate:
                history.append({"type": "reservation", "data": res_data})

        for sess_data in sessions_data.values():
            if sess_data.get("license_plate") == license_plate or sess_data.get("licenseplate") == license_plate:
                history.append({"type": "session", "data": sess_data})
        
        history.sort(key=lambda x: x["data"].get("start_time", ""))

        self.send_json_response(200, "application/json", history)

    @login_required 
    def _handle_get_parking_lot_sessions(self, session_user):
        parking_lots = load_parking_lot_data()
        lid = self.path.split("/")[-1]
        if not lid.isdigit():
            self.send_json_response(400,"application/json",{"error":"Invalid session id"}); return
        
        if lid not in parking_lots:
            self.send_json_response(404, "application/json", {"error": "Parking lot not found"})
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
            self.send_json_response(200, "application/json", rsessions)
        else:
            sid = self.path.split("/")[-1]
            if not (session_user["role"] == "ADMIN") and not session_user["username"] == sessions[sid].get("user"):
                self.send_json_response(403, "application/json", {"error": "Access denied"})
                return
            self.send_json_response(200, "application/json", sessions[sid])