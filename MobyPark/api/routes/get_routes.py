from storage_utils import load_json, save_user_data, load_parking_lot_data, save_parking_lot_data, load_reservation_data, save_reservation_data, load_payment_data, save_payment_data, load_vehicles_data, save_vehicles_data,save_vehicles_data
from authentication import login_required, roles_required
import session_calculator as sc
import authentication

class get_routes:
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
    
    @login_required
    def _handle_get_reservations(self, session_user):
        reservations = load_reservation_data()
        print(f"DEBUG: In _handle_get_reservations. Session User: {session_user}")
        print(f"DEBUG: Raw Reservations Data: {reservations}")
        user_reservations = {rid: res for rid, res in reservations.items() if res.get("user") == session_user["username"] or session_user["role"] == "ADMIN"}
        self._send_json_response(200, "application/json", user_reservations)

    @login_required
    def _handle_get_payments(self, session_user):
        payments = []
        for payment in load_payment_data():
            if payment.get("initiator") == session_user["username"] or payment.get("processed_by") == session_user["username"] or session_user["role"] == "ADMIN":
                payments.append(payment)
        self._send_json_response(200, "application/json", payments)
    
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
    
    @login_required
    def _handle_get_vehicles(self, session_user):
        vehicles_data = load_vehicles_data()

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
    
    def _handle_get_parking_lot_details(self):
        lid = self.path.split("/")[2]
        parking_lots = load_parking_lot_data()
        
        if lid not in parking_lots:
            self._send_json_response(404, "application/json", {"error": "Parking lot not found"})
            return

        self._send_json_response(200, "application/json", parking_lots[lid])
    
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
