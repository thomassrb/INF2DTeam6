import re
from MobyPark.api.server import login_required, roles_required
from storage_utils import load_json, save_user_data, load_parking_lot_data, save_parking_lot_data, load_reservation_data, save_reservation_data, load_payment_data, save_payment_data, load_vehicles_data, save_vehicles_data,save_vehicles_data
from MobyPark.api.authentication import PasswordManager
from datetime import datetime
password_manager = PasswordManager()

class put_Routes: 
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
        

    @roles_required(['ADMIN'])
    def _handle_update_parking_lot_by_id(self, session_user):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return
        parts = [p for p in self.path.split('/') if p]
        if len(parts) < 2: return self._send_json_response(400, "application/json", {"error": "id missing"})
        lid = str(parts[1])
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
            data["password"] = password_manager.hash_password(data["password"])
        
        target_user.update(data)
        save_user_data(users)
        self.audit_logger.audit(session_user, action="update_profile", target=target_user_id)
        self._send_json_response(200, "application/json", {"message": "User updated successfully"})

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
        
        vehicles = load_vehicles_data()
        
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
        save_vehicles_data(vehicles)
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


