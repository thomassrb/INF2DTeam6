from datetime import datetime
from storage_utils import load_json, save_user_data

class POST:
    def _handle_register(self):
        from server import RequestHandler
        data = RequestHandler._get_request_data()
        
        valid, error = RequestHandler._validate_data(data, 
            required_fields={'username': str, 'password': str, 'name': str, 'phone': str, 'email': str, 'birth_year': (int, str)},
            optional_fields={'role': str},
            allow_unknown=True
        )
        if not valid:
            RequestHandler._send_response(400, "application/json", error)
            return
        
        username = data['username']
        password = data['password']
        name = data['name']
        phone_number = data['phone']
        email = data['email']
        birth_year = data['birth_year']
        
        if not isinstance(password, str) or not password:
            RequestHandler._send_response(400, "application/json", {"error": "Invalid password", "field": "password"})
            return
        
        hashed_password = RequestHandler._hash_password(password)
        users = load_json('users.json')
        
        if any(user['username'] == username for user in users):
            RequestHandler._send_response(409, "application/json", {"error": "Username already taken"})
            return
        
        new_id = str(max(int(u.get("id", 0)) for u in users) + 1) if users else "1"
        users.append({
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
        })
        save_user_data(users)
        RequestHandler._send_response(201, "application/json", {"message": "User created"})
