
import os
import sys
import pathlib

project_root = str(pathlib.Path(__file__).resolve().parent.parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from MobyPark.api.authentication import login_required, roles_required
from MobyPark.api.app import access_vehicles, access_parkinglots, access_payments, access_reservations, access_sessions, access_users, connection
from MobyPark.api.Models.User import User


class delete_routes:
    @roles_required(['ADMIN'])
    def _handle_delete_parking_lot(self, session_user):
        lid = None
        path_parts = self.path.split('/')
        if len(path_parts) > 2 and path_parts[2]:
            lid = path_parts[2]

        if lid:
            parking_lot = access_parkinglots.get_parking_lot(id=lid)
            if not parking_lot:
                self.send_json_response(404, "application/json", {"error": "Parking lot not found"})
                return
            access_parkinglots.delete_parking_lot(parkinglot=parking_lot)
            self.audit_logger.audit(session_user, action="delete_parking_lot", target=lid)
            self.send_json_response(200, "application/json", {"message": f"Parking lot {lid} deleted"})
        else:
            connection.cursor.execute("TRUNCATE TABLE parking_lots, parking_lots_coordinates") # lijkt me erg riskant
            self.audit_logger.audit(session_user, action="delete_all_parking_lots")
            self.send_json_response(200, "application/json", {"message": "All parking lots deleted"})
    

    @login_required
    def _handle_delete_reservation(self, session_user: User):
        rid = self.path.replace("/reservations/", "")
        reservation = access_reservations.get_reservation(id=rid)
        parking_lots = access_parkinglots.get_all_parking_lots()

        if not rid:
            if session_user.role == "ADMIN":
                connection.cursor.execute("TRUNCATE TABLE reservations")

                for parking_lot in parking_lots:
                    parking_lot.reserved = 0
                    access_parkinglots.update_parking_lot(parkinglot=parking_lot)
                
                self.audit_logger.audit(session_user, action="delete_all_reservations_by_admin")
                self.send_json_response(200, "application/json", {"status": "All reservations deleted by admin"})
                return
            else:
                user_reservations_to_delete = access_reservations.get_reservations_by_user(user=session_user)
                if not user_reservations_to_delete:
                    self.send_json_response(404, "application/json", {"error": "No reservations found for this user"})
                    return
                for reservation in user_reservations_to_delete:
                    parking_lot = reservation.parking_lot
                    parking_lot.reserved -= 1
                    access_parkinglots.update_parking_lot(parkinglot=parking_lot)
                    access_reservations.delete_reservation(reservation=reservation)
                self.audit_logger.audit(session_user, action="delete_all_user_reservations")
                self.send_json_response(200, "application/json", {"status": "All user reservations deleted"})
                return

        if not reservation:
            self.send_json_response(404, "application/json", {"error": "Reservation not found"})
            return

        if not (session_user.role == "ADMIN") and not session_user == reservation.user:
            self.send_json_response(403, "application/json", {"error": "Access denied"})
            return

        parking_lot = reservation.parking_lot
        if parking_lot.reserved > 0:
            parking_lot.reserved -= 1
        else:
            self.send_json_response(400, "application/json", {"error": "Parking lot reserved count is already zero"})
            return

        access_parkinglots.update_parking_lot(parkinglot=parking_lot)
        access_reservations.delete_reservation(reservation=reservation)
        self.send_json_response(200, "application/json", {"status": "Deleted"})

    @login_required
    def _handle_delete_vehicle(self, session_user):
        vid = self.path.replace("/vehicles/", "")
        vehicle = access_vehicles.get_vehicle(id=vid)

        if not vehicle:
            self.send_json_response(404, "application/json", {"error": "Vehicle not found"})
            return
        else:
            if session_user.role != "ADMIN" and session_user != vehicle.user:
                self.send_json_response(403, "application/json", {"error": "Access denied"})
                return

        access_vehicles.delete_vehicle(vehicle=vehicle)
        self.audit_logger.audit(session_user, action="delete_vehicle", target=vid)
        self.send_json_response(200, "application/json", {"status": "Deleted"})

    @roles_required(['ADMIN'])
    def _handle_delete_session(self, session_user):
        sid = self.path.split("/")[2]
        session = access_sessions.get_session(id=sid)
        
        if not sid.isnumeric():
            self.send_json_response(400, "application/json", {"error": "Session ID is required, cannot delete all sessions"})
            return
                
        if not session:
            self.send_json_response(404, "application/json", {"error": "Session not found"})
            return
        
        access_sessions.delete_session(session=session)
        self.audit_logger.audit(session_user, action="delete_session", target={"parking_lot": session.parking_lot.id, "session": sid})
        self.send_json_response(200, "application/json", {"message": "Session deleted"})