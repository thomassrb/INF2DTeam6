import time
import json
import logging
from datetime import datetime
from pathlib import Path
import os

log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

logger = logging.getLogger("performance")
logger.setLevel(logging.INFO)

if not logger.handlers:
    log_file = log_dir / f"perf-{datetime.now().strftime('%d-%m-%Y')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)

    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_record = {
                "endpoint": getattr(record, 'endpoint', ''),
                "duration_ms": getattr(record, 'duration_ms', 0),
                "timestamp": datetime.now().isoformat(),
                "level": record.levelname
            }
            return str(log_record)

    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)
    logger.propagate = False

class PerformanceTracer:
    def __init__(self, app, alert_threshold_ms=300):
        self.app = app
        self.alert_threshold_ms = alert_threshold_ms

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        start_time = time.time()
        request_path = scope.get("path", "")

        async def send_wrapper(response):
            if response["type"] == "http.response.start":
                duration_ms = (time.time() - start_time) * 1000
                rounded_duration = round(duration_ms, 2)
                
                log_record = logging.LogRecord(
                    name="performance",
                    level=logging.INFO,
                    pathname=__file__,
                    lineno=0,
                    msg="",
                    args=(),
                    exc_info=None
                )
                log_record.endpoint = request_path
                log_record.duration_ms = rounded_duration
                logger.handle(log_record)

                if duration_ms > self.alert_threshold_ms:
                    logger.warning(
                        f"Slow request detected: {request_path} took {rounded_duration:.2f}ms",
                        extra={"endpoint": request_path, "duration_ms": rounded_duration}
                    )

                if "headers" not in response:
                    response["headers"] = []
                response["headers"].append(
                    [b"x-response-time", f"{rounded_duration:.2f}ms".encode()]
                )

            await send(response)

        await self.app(scope, receive, send_wrapper)