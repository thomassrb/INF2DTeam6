import json
import importlib
from datetime import datetime
import random
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'MobyPark', 'api')))
from storage_utils import save_user_data # dit mnu, het werkt alsnog

def generate_mock_users(num_users=40):
    first_names = [
        "Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy",
        "Karl", "Linda", "Mike", "Nancy", "Oscar", "Pat", "Quinn", "Rachel", "Steve", "Tina",
        "Uma", "Victor", "Wendy", "Xavier", "Yara", "Zack", "Liam", "Olivia", "Noah", "Emma",
        "Oliver", "Ava", "Elijah", "Charlotte", "William", "Sophia", "James", "Amelia", "Benjamin", "Isabella"
    ]

    users = []
    for i in range(1, num_users + 1):
        username = f"user{i}"
        password = f"password{i}"
        name = f"{random.choice(first_names)} Smith"
        try:
            bcrypt = importlib.import_module("bcrypt")
        except ImportError as exc:
            raise RuntimeError("bcrypt is not installed. Please install with: pip install bcrypt") from exc
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode("utf-8")
        role = "ADMIN" if i % 25 == 0 else "USER"
        created_at = datetime.now().strftime("%Y-%m-%d")

        user = {
            "id": str(i),
            "username": username,
            "password": hashed_password,
            "name": name,
            "role": role,
            "created_at": created_at
        }
        users.append(user)
    return users

if __name__ == "__main__":
    mock_users = generate_mock_users()
    save_user_data(mock_users)
    print(f"Successfully generated {len(mock_users)} mock users and saved to data/users.json")
