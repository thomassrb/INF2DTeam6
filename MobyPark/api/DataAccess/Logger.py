from MobyPark.api.Models.User import User
import logging
import json
from datetime import datetime

class Logger:
    def __init__(self, path):
        self.path = path
        self.logger = logging.getLogger("json_logger")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(JsonFormatter())
        self.logger.addHandler(handler)
        

    def log(self, user:User, endpoint:str):
        data = {
            "endpoint": endpoint,
            "user": user.username,
            "role": user.role,
            "timestamp": datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S")
        }
        self.logger.info(data)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "endpoint": record.endpoint,
            "user": record.user,
            "role": record.role,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        }
        return json.dumps(log_entry)