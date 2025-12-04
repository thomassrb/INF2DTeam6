import re
from authentication import PasswordManager, login_required, roles_required
from datetime import datetime
from app import access_vehicles, access_parkinglots, access_payments, access_reservations, access_sessions, access_users, connection
from MobyPark.api.Models.TransanctionData import TransactionData
password_manager = PasswordManager()


class put_routes: 
    @roles_required(['ADMIN'])
    def _handle_update_parking_lot(self, session_user):
        lid = self.path.split("/")[2]
        parking_lot = access_parkinglots.get_parking_lot(id=lid)
        
        if not parking_lot:
            self.send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return
    
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        for key, value in data.items():
            if hasattr(parking_lot, key):
                setattr(parking_lot, key, value)
        access_parkinglots.update_parking_lot(parkinglot=parking_lot)
        self.audit_logger.audit(session_user, action="update_parking_lot", target=lid)
        self.send_json_response(200, "application/json", {"message": "Parking lot modified"})
        

    @roles_required(['ADMIN'])
    def _handle_update_parking_lot_by_id(self, session_user):
        lid = self.path.split("/")[2]
        parking_lot = access_parkinglots.get_parking_lot(id=lid)
        
        if not parking_lot:
            self.send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return
        parts = [p for p in self.path.split('/') if p]
        if len(parts) < 2: return self.send_json_response(400, "application/json", {"error": "id missing"})
        lid = str(parts[1])
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        for key, value in data.items():
            if hasattr(parking_lot, key):
                setattr(parking_lot, key, value)
        access_parkinglots.update_parking_lot(parkinglot=parking_lot)
        self.audit_logger.audit(session_user, action="update_parking_lot", target=lid)
        self.send_json_response(200, "application/json", {"message": "Parking lot modified"})


    @login_required
    def _handle_update_profile_by_id(self, session_user):
        match = re.match(r"^/profile/([^/]+)$", self.path)
        if not match:
            self.send_json_response(400, "application/json", {"error": "Invalid URL format"})
            return
        
        target_user_id = match.group(1)
        target_user = access_users.get_user_byid(id=target_user_id)
        
        if not target_user:
            self.send_json_response(404, "application/json", {"error": "User not found"})
            return
        
        is_admin = session_user.role == "ADMIN"
        
        if not is_admin and session_user.id != target_user_id:
            self.send_json_response(403, "application/json", {"error": "Access denied. You can only view your own profile."})
            return
        
        data = self.get_request_data()
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return

        if data.get("password"):
            data["password"] = password_manager.hash_password(data["password"])
        
        for key, value in data.items():
            if hasattr(target_user, key):
                setattr(target_user, key, value)
        access_users.update_user(user=target_user)
        self.audit_logger.audit(session_user, action="update_profile", target=target_user_id)
        self.send_json_response(200, "application/json", {"message": "User updated successfully"})


    @login_required
    def _handle_update_reservation(self, session_user):
        data = self.get_request_data()
        rid = self.path.replace("/reservations/", "")
        reservation = access_reservations.get_reservation(id=rid)
        
        if not reservation:
            self.send_json_response(404, "application/json", {"error": "Reservation not found"})
            return
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        if session_user.role == "ADMIN":
            if "user" not in data:
                data["user"] = session_user.username
            elif data["user"] != session_user.username:
                self.send_json_response(403, "application/json", {"error": "Non-admin users cannot update reservations for other users"})
                return
        else:
            if "user" in data and data["user"] != session_user.username:
                self.send_json_response(403, "application/json", {"error": "Non-admin users cannot update reservations for other users"})
                return
            data["user"] = session_user.username
        
        for key, value in data.items():
            if hasattr(reservation, key):
                setattr(reservation, key, value)
        access_reservations.update_reservation(reservation=reservation)
        self.send_json_response(200, "application/json", {"status": "Updated", "reservation": data})

    
    @login_required
    def _handle_update_vehicle(self, session_user):
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        vid = self.path.replace("/vehicles/", "")
        vehicle = access_vehicles.get_vehicle(id=vid)
 
        if not vehicle:
            self.send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
        
        if vehicle.user != session_user:
            self.send_json_response(403, "application/json", {"error": "No access to this vehicle"})
        
        for key, value in data.items():
            if hasattr(vehicle, key):
                setattr(vehicle, key, value)
        access_vehicles.update_vehicle(vehicle=vehicle)
        self.audit_logger.audit(session_user, action="update_vehicle", target=vid, extra={"name": data["name"]})
        self.send_json_response(200, "application/json", {"status": "Success", "vehicle": vid})

    @login_required
    def _handle_update_payment(self, session_user):
        pid = self.path.replace("/payments/", "")
        payment = access_payments.get_payment(id=pid)
        data = self.get_request_data()
        
        valid, error = self.data_validator.validate_data(data)
        if not valid:
            self.send_json_response(400, "application/json", error)
            return
        
        if not payment:
            self.send_json_response(404, "application/json", {"error": "Payment not found!"})
            return
        
        if payment.hash != data['validation']:
            self.send_json_response(401, "application/json", {"error": "Validation failed", "info": "The validation of the security hash could not be validated for this transaction."})
            return
        
        for key, value in data['t_data'].items():
            if hasattr(payment.t_data, key):
                setattr(payment.t_data, key, value)

        payment["completed"] = True
        payment["completed_at"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        access_payments.update_payment(payment=payment)
        self.audit_logger.audit(session_user, action="update_payment", target=pid)
        self.send_json_response(200, "application/json", {"status": "Success", "payment": payment})


