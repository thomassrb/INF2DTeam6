
from storage_utils import load_json, save_data, save_parking_lot_data, load_parking_lot_data, save_reservation_data, load_reservation_data
from MobyPark.api.server import login_required, roles_required


class delete_routes:
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