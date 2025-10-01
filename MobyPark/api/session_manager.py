sessions = {}

def add_session(token, user):
    sessions[token] = user

def remove_session(token):
    return sessions.pop(token, None)

def get_session(token):
    return sessions.get(token)

def update_session_user(token, user_data):
    if token in sessions:
        sessions[token].update(user_data)