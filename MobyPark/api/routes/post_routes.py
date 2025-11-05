import uuid
import hashlib
import bcrypt
from datetime import datetime
from storage_utils import load_json, save_user_data, load_parking_lot_data, save_parking_lot_data

# POST (post_routes.py)
# - handle_register(self)
# - handle_login(self)
# - _handle_create_parking_lot
# - _handle_create_reservation
# - _handle_create_vehicle
# - _handle_create_payment
# - _handle_start_session
# - _handle_stop_session
# - _handle_refund_payment
# - _handle_debug_reset

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


    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users = load_json('users.json')

    if any(user['username'] == username for user in users):
        handler.send_json_response(409, "application/json", {"error": "Username already taken"})
        return

    new_id = str(max(int(u.get("id", 0)) for u in users) + 1) if users else "1"
    new_user = {
        'id': new_id,
        'username': username,
        'password': hashed_password,
        'name': name,
        'phone': phone_number,
        'email': email,
        'birth_year': birth_year,
        'role': data.get('role', 'USER'),
        'active': True,
        'created_at': datetime.now().strftime("%Y-%m-%d")
    }
    users.append(new_user)
    save_user_data(users)
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

    users = load_json('users.json')
    user_to_authenticate = None
    print(f"DEBUG: Searching for user '{username}' in users list of type {type(users)}")
    for u in users:
        print(f"DEBUG: Checking user: {u.get('username')}")
        if u.get("username") == username:
            user_to_authenticate = u
            print(f"DEBUG: Found user {username}: {user_to_authenticate}")
            break

    # COMMENTS TOEVOEGEN VOOR ONDERSTAAND STATEMENT
    if user_to_authenticate:
        if user_to_authenticate.get("password", "").startswith("$2b$"):
            if bcrypt.checkpw(password.encode('utf-8'), user_to_authenticate["password"].encode('utf-8')):
                print(f"DEBUG: Bcrypt match for user {username}")
                token = str(uuid.uuid4())
                handler.session_manager.add_session(token, user_to_authenticate)
                handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                return
        else:
            hashed_password_input = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if hashed_password_input == user_to_authenticate.get("password", ""):
                print(f"DEBUG: SHA256 match for user {username}")
                token = str(uuid.uuid4())
                handler.session_manager.add_session(token, user_to_authenticate)
                handler.send_json_response(200, "application/json", {"message": "User logged in", "session_token": token})
                return

    print(f"DEBUG: Login failed for username: {username}. Provided password: {password}. Stored user: {user_to_authenticate}")
    handler.send_json_response(401, "application/json", {"error": "Invalid credentials"})
