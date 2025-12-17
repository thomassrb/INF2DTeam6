from MobyPark.api.Models.User import User
import logging
import json
from datetime import datetime
from typing import Union, Dict, Any

class Logger:
    def __init__(self, path):
        self.path = path
        self.logger = logging.getLogger("mobypark")
        self.logger.setLevel(logging.INFO)
        
        if self.logger.handlers:
            self.logger.handlers = []
            
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(JsonFormatter())
        self.logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console_handler)

    def log(self, user: Union[str, object], endpoint: str, role: str = "USER"):
        username = user.username if hasattr(user, 'username') else str(user)
        user_role = user.role if hasattr(user, 'role') else role
        
        self.logger.info(
            "API Request",
            extra={
                'endpoint': endpoint,
                'user': username,
                'role': user_role
            }
        )


class JsonFormatter(logging.Formatter):
    def format(self, record):
        record_copy = record.__dict__.copy()
        
        message = record.getMessage()
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'message': message,
            'endpoint': getattr(record, 'endpoint', ''),
            'user': getattr(record, 'user', ''),
            'role': getattr(record, 'role', ''),
        }
        
        return json.dumps(log_entry)