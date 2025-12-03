import requests
import time
import threading
import statistics
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"
LOGIN_URL = f"{BASE_URL}/login"
TEST_ENDPOINT = f"{BASE_URL}/parking-lots"  # Of een ander endpoint
NUM_THREADS = 50
NUM_REQUESTS = 100
TEST_USER = "performanceuser"
TEST_PASS = "password123"

class PerformanceTester:
    def __init__(self):
        self.results = []
        self.lock = threading.Lock()
        self.token = None

    def login(self):
        """Login en sla token op"""
        try:
            response = requests.post(LOGIN_URL, json={
                "username": TEST_USER,
                "password": TEST_PASS
            })
            if response.status_code == 200:
                self.token = response.json().get("token")
                return True
            else:
                print(f"Login mislukt: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Login error: {e}")
        return False

    def make_request(self, request_id):
        """Maak een verzoek naar het endpoint"""
        start_time = time.time()
        success = False
        status_code = None
        
        try:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            response = requests.get(TEST_ENDPOINT, headers=headers)
            duration = (time.time() - start_time) * 1000  # naar milliseconden
            status_code = response.status_code
            
            if 200 <= status_code < 300:
                success = True
                print(f"Request {request_id}: Succes ({duration:.2f}ms)")
            else:
                print(f"Request {request_id}: Fout {status_code} ({duration:.2f}ms)")
                
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            print(f"Request {request_id}: Error - {str(e)[:50]}...")

        with self.lock:
            self.results.append({
                "success": success,
                "duration_ms": duration,
                "status_code": status_code,
                "timestamp": datetime.now().isoformat()
            })

    def run_test(self):
        """Voer de load test uit"""
        print(f"\n=== Start performance test ===")
        print(f"Endpoint: {TEST_ENDPOINT}")
        print(f"Aantal gelijktijdige gebruikers: {NUM_THREADS}")
        print(f"Totaal aantal verzoeken: {NUM_REQUESTS}")
        
        self.results = []
        start_time = time.time()
        
        threads = []
        for i in range(NUM_REQUESTS):
            t = threading.Thread(target=self.make_request, args=(i,))
            threads.append(t)
            t.start()
            
            if len(threads) >= NUM_THREADS:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        total_time = (time.time() - start_time) * 1000
        successful = [r for r in self.results if r["success"]]
        durations = [r["duration_ms"] for r in successful]
        
        stats = {
            "endpoint": TEST_ENDPOINT,
            "total_requests": len(self.results),
            "successful_requests": len(successful),
            "failed_requests": len(self.results) - len(successful),
            "success_rate": len(successful) / len(self.results) * 100 if self.results else 0,
            "total_time_ms": total_time,
            "requests_per_second": len(self.results) / (total_time / 1000) if total_time > 0 else 0,
            "avg_response_time_ms": statistics.mean(durations) if durations else 0,
            "min_response_time_ms": min(durations) if durations else 0,
            "max_response_time_ms": max(durations) if durations else 0,
            "p90_response_time_ms": statistics.quantiles(durations, n=10)[-1] if durations and len(durations) >= 10 else 0
        }
        
        print("\n=== Test samenvatting ===")
        print(f"Totaal tijd: {stats['total_time_ms']/1000:.2f} seconden")
        print(f"Requests per seconde: {stats['requests_per_second']:.2f}")
        print(f"Succespercentage: {stats['success_rate']:.1f}%")
        print(f"Gemiddelde responstijd: {stats['avg_response_time_ms']:.2f}ms")
        print(f"Minimale responstijd: {stats['min_response_time_ms']:.2f}ms")
        print(f"Maximale responstijd: {stats['max_response_time_ms']:.2f}ms")
        print(f"P90 responstijd: {stats['p90_response_time_ms']:.2f}ms")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"performance_results_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump({
                "config": {
                    "base_url": BASE_URL,
                    "endpoint": TEST_ENDPOINT,
                    "num_threads": NUM_THREADS,
                    "num_requests": NUM_REQUESTS,
                    "test_time": datetime.now().isoformat()
                },
                "stats": stats,
                "all_requests": self.results
            }, f, indent=2)
        
        print(f"\nGedetailleerde resultaten opgeslagen in: {filename}")
        return stats

if __name__ == "__main__":
    tester = PerformanceTester()
    if tester.login():
        tester.run_test()
    else:
        print("Kon niet inloggen. Controleer de inloggegevens en of de server draait.")