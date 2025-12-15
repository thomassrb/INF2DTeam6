from MobyPark.api.Models.User import User
from logging.handlers import TimedRotatingFileHandler
import os
import logging
import json
from datetime import datetime

def setup_logger():
    log_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "logs")
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("json_logger")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    handler = TimedRotatingFileHandler(
    os.path.join(log_dir, "access.log"),
    when="midnight",
    utc=True
    )
    handler.namer = lambda name: name.replace("access.log.", "access-") + ".log"

    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)

    return logger


def log(user: User, endpoint: str):
    logger = setup_logger()

    logger.info(
        "access",
        extra={
            "endpoint": endpoint,
            "user": user.username,
            "role": user.role,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "endpoint": record.endpoint,
            "user": record.user,
            "role": record.role,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        }
        return json.dumps(log_entry)