import bcrypt
from storage_utils import load_json, save_user_data
from authentication import extract_bearer_token

# PUT (put_routes.py)
# - handle_update_profile(self, self.get_user_from_session())
# - _handle_update_parking_lot
# - _handle_update_reservation
# - _handle_update_vehicle
# - _handle_update_payment

def handle_update_profile(handler, session_user):
    data = handler.get_request_data()
    
    valid, error = handler.data_validator.validate_data(data,
        optional_fields={'name': str, 'password': str}
    )
    if not valid:
        handler.send_json_response(400, "application/json", error)
        return

    auth_header = handler.headers.get('Authorization')
    raw_token = extract_bearer_token(handler.headers)

    users = load_json('users.json')
    updated_user = None
    for i, user in enumerate(users):
        if user["username"] == session_user["username"]:
            for key, value in data.items():
                if key == "password":
                    users[i][key] = bcrypt.hashpw(value.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                elif key != "username":
                    users[i][key] = value
            updated_user = users[i]
            break
    save_user_data(users)

    if updated_user and raw_token:
        handler.session_manager.update_session_user(raw_token, updated_user)
    handler.audit_logger.audit(session_user, action="update_profile")
    handler.send_json_response(200, "application/json", {"message": "User updated successfully"})