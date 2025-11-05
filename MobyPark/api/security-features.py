import threading
import time

class security_features:
    pass

class session_timer:    
    def __init__(self, timeout=1800):
        self.timeout = timeout
        self.last_activity = time.time()
        self.session_expiry_maintenance()

        def update_activity(self):
            self.last_activity = time.time()

        def session_expiry_maintenance(self):
                timer = threading.Timer(600, self.session_expiry_maintenance)
                timer.daemon = True
                timer.start()
                if time.time() - self.last_activity > self.timeout:
                    self._handle_logout()