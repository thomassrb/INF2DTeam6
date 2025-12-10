from MobyPark.api.Models.User import User
import logging
import json
from datetime import datetime

class Logger:
    def __init__(self, file_path):
        pass

    
    def log(user:User, endpoint:str):
        logger = logging.getLogger("json_logger")
        logger.setLevel(logging.INFO)

        handler = logging.FileHandler("access-dd-mm-yyyy.log", encoding="utf-8")
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)




class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "endpoint": record.endpoint,
            "user": record.user,
            "role": record.role,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        }
        return json.dumps(log_entry)