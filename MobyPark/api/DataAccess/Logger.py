from MobyPark.api.Models.User import User
from logging.handlers import TimedRotatingFileHandler
import os
import logging
import json
from datetime import datetime
from typing import Union, Dict, Any


class JsonFormatter(logging.Formatter):
    def format(self, record):
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


class Logger:
    def __init__(self, path: str):
        self.path = path
        self.logger = logging.getLogger("mobypark")
        self.logger.setLevel(logging.INFO)

        # Prevent duplicate handlers on reload
        if self.logger.handlers:
            self.logger.handlers = []

        # File logging
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file_handler = TimedRotatingFileHandler(
            path,
            when="midnight",
            utc=True,
            encoding="utf-8"
        )
        file_handler.setFormatter(JsonFormatter())
        self.logger.addHandler(file_handler)

        # Console logging
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        self.logger.addHandler(console_handler)

    def log(self, user: Union[User, Any], endpoint: str):
        username = user.username if hasattr(user, 'username') else str(user)
        role = user.role if hasattr(user, 'role') else 'unknown'

        self.logger.info(
            "API Request",
            extra={
                'endpoint': endpoint,
                'user': username,
                'role': role
            }
        )

    def error(self, message: str):
        self.logger.error(message)