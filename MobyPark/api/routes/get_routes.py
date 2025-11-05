import re
from storage_utils import load_json
from authentication import extract_bearer_token

# GET (get_routes.py)
# - _handle_index
# - _handle_favicon
# - _handle_get_parking_lots
# - handle_get_profile(self, self.get_user_from_session())
# - handle_logout(self)
# - _handle_get_reservations
# - _handle_get_payments
# - _handle_get_billing
# - _handle_get_vehicles
# - _handle_get_parking_lot_details
# - _handle_get_reservation_details
# - _handle_get_payment_details
# - _handle_get_user_billing
# - _handle_get_vehicle_details
# - _handle_get_vehicle_reservations
# - _handle_get_vehicle_history
# - _handle_get_parking_lot_sessions
# - handle_get_profile_by_id(self, self.get_user_from_session())


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
