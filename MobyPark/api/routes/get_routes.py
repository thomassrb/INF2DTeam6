import re

from MobyPark.api.app import (
    access_vehicles,
    access_parkinglots,
    access_payments,
    access_reservations,
    access_sessions,
    access_users,
)
from MobyPark.api.authentication import extract_bearer_token, login_required, roles_required
from MobyPark.api import session_calculator as sc
from MobyPark.api import authentication

from MobyPark.api.Models.User import User



class get_routes:
    def handle_get_profile(handler, session_user: User):
        profile_data = {
        "username": session_user.username,
        "role": session_user.role,
        "name": session_user.name,
        "email": session_user.email,
        "phone": session_user.phone,
        "birth_year": session_user.birth_year,
        "created_at": session_user.created_at.strftime("%d-%m-%Y"),
    }

        handler.send_json_response(200, "application/json", profile_data)


    def handle_get_profile_by_id(handler, session_user: User):
        match = re.match(r"^/profile/([^/]+)$", handler.path)
        if not match:
            handler.send_json_response(400, "application/json", {"error": "Invalid URL format"})
            return
        
        target_user_id = match.group(1)
        target_user = access_users.get_user_byid(id=target_user_id)
        
        if not target_user:
            handler.send_json_response(404, "application/json", {"error": "User not found"})
            return
        
        is_admin = session_user.role == "ADMIN"
        
        if not is_admin and session_user.id != target_user_id:
            handler.send_json_response(403, "application/json", {"error": "Access denied. You can only view your own profile."})
            return
        
        profile_data = {
            "username": target_user.username,
            "role": target_user.role,
            "name": target_user.name,
            "email": target_user.email,
            "phone": target_user.phone,
            "birth_year": target_user.birth_year,
            "created_at": target_user.created_at.strftime("%d-%m-%Y"),
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
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write("👍 200 OK - MobyPark API is running".encode('utf-8'))


    def _handle_favicon(self):
        self.send_json_response(204, "image/x-icon", "")


    def _handle_get_parking_lots(self):
        parking_lots = access_parkinglots.get_all_parking_lots()
        self.send_json_response(200, "application/json", parking_lots)
    

    @login_required
    def _handle_get_reservations(self, session_user: User):
        if session_user.role == "ADMIN":
            self.send_json_response(200, "application/json", access_reservations.get_all_reservations())
        else:
            reservations = access_reservations.get_reservations_by_user(user=session_user)
            self.send_json_response(200, "application/json", reservations)


    @login_required
    def _handle_get_payments(self, session_user: User):
        if session_user.role == "ADMIN":
            self.send_json_response(200,  "application/json", access_payments.get_all_payments())
        else:
            payments = access_payments.get_payments_by_user(user_id=session_user)
            self.send_json_response(200, "application/json", payments)
    

    @login_required
    def _handle_get_billing(self, session_user):
        sessions = access_sessions.get_sessions_byuser(user=session_user)
        data = list()
        
        for session in sessions:
            amount, hours, days = sc.calculate_price(session.parking_lot, session)
            transaction = sc.generate_payment_hash(session.id, session)
            payed = sc.check_payment_amount(transaction)
            data.append({
                "session": {
                    "licenseplate": session.licenseplate,
                    "started": session.started,
                    "stopped": session.stopped,
                    "hours": hours,
                    "days": days
                    },
                "parking": {
                    "name": session.parking_lot.name, 
                    "location": session.parking_lot.location, 
                    "tariff": session.parking_lot.tariff,
                    "daytariff": session.parking_lot.daytariff
                    },
                "amount": amount,
                "thash": transaction,
                "payed": payed,
                "balance": amount - payed
            })
        self.send_json_response(200, "application/json", data)
    

    @login_required
    def _handle_get_vehicles(self, session_user: User):
        if session_user.role == "ADMIN":
            self.send_json_response(200, "application/json", access_vehicles.get_all_vehicles())
        else:
            user_vehicles = access_vehicles.get_vehicles_byuser(user=session_user)
            self.send_json_response(200, "application/json", user_vehicles)


    def _handle_get_parking_lot_details(self):
        lid = self.path.split("/")[2]
        parking_lot = access_parkinglots.get_parking_lot(id=lid)
        
        if lid is None:
            self.send_json_response(404, "application/json", {"error": "Parking lot not found"})
        else:
            self.send_json_response(200, "application/json", parking_lot)
    

    @login_required
    def _handle_get_reservation_details(self, session_user: User):
        rid = self.path.replace("/reservations/", "")
        reservation = access_reservations.get_reservation(id=rid)
        if rid is None:
            self.send_json_response(404, "application/json", {"error": "Reservation not found"})
            return

        if not (session_user.role == "ADMIN") and not session_user.id == reservation.user.id:
            self.send_json_response(403, "application/json", {"error": "Access denied"})
            return
        
        self.send_json_response(200, "application/json", reservation)


    @login_required
    def _handle_get_payment_details(self):
        session_user = authentication.get_user_from_session(self)
        pid = self.path.replace("/payments/", "")
        payment = access_payments.get_payment(id=pid)
        if not payment:
            self.send_json_response(404, "application/json", {"error": "Payment not found!"})
            return
        if (session_user.role != "ADMIN") and (payment.user.id != session_user.id):
            self.send_json_response(403, "application/json", {"error": "Access denied"})
            return
        
        self.send_json_response(200, "application/json", payment)


    @roles_required(['ADMIN'])
    def _handle_get_user_billing(self):
        user = self.path.replace("/billing/", "")
        sessions = access_sessions.get_sessions_byuser(user=user)
        data = list()
        
        for session in sessions:
            amount, hours, days = sc.calculate_price(session.parking_lot, session)
            transaction = sc.generate_payment_hash(session.id, session)
            payed = sc.check_payment_amount(transaction)
            data.append({
                "session": {
                    "licenseplate": session.licenseplate,
                    "started": session.started,
                    "stopped": session.stopped,
                    "hours": hours,
                    "days": days
                    },
                "parking": {
                    "name": session.parking_lot.name, 
                    "location": session.parking_lot.location, 
                    "tariff": session.parking_lot.tariff,
                    "daytariff": session.parking_lot.daytariff
                    },
                "amount": amount,
                "thash": transaction,
                "payed": payed,
                "balance": amount - payed
            })
        self.send_json_response(200, "application/json", data)
