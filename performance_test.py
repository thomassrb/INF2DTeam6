import time
import requests
from typing import Dict, List, Tuple
import statistics
import json
from datetime import datetime


BASE_URL = "http://localhost:8000"
TEST_USER = {
    "username": "performanceuser",
    "password": "password123"
}

class PerformanceTester:
    def __init__(self):
        self.session = requests.Session()
        self.auth_token = None
        self.results = []
    
    def login(self):
        """Login and retrieve an authentication token."""
        try:
            response = self.session.post(
                f"{BASE_URL}/login",
                json={"username": TEST_USER["username"], "password": TEST_USER["password"]}
            )
            response.raise_for_status()
            self.auth_token = response.json().get("session_token")
            self.session.headers.update({"Authorization": f"Bearer {self.auth_token}"})
            return True
        except Exception as e:
            print(f"Login failed: {e}")
            return False
    
    def measure_endpoint(self, method: str, endpoint: str, json_data: dict = None, params: dict = None, name: str = None) -> dict:
        """Measure the response time of a given endpoint."""
        if name is None:
            name = f"{method} {endpoint}"
        
        url = f"{BASE_URL}{endpoint}"
        times = []
        status_codes = []
        
        for _ in range(10):
            try:
                start_time = time.time()
                response = self.session.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params
                )
                elapsed = (time.time() - start_time) * 1000  # milliseconds converter
                times.append(elapsed)
                status_codes.append(response.status_code)
                time.sleep(0.1)
            except Exception as e:
                print(f"Error during {name}: {e}")
                return None
        
        if not times:
            return None
            
        result = {
            "endpoint": name,
            "timestamp": datetime.now().isoformat(),
            "request_count": len(times),
            "successful_requests": sum(1 for code in status_codes if 200 <= code < 300),
            "avg_response_time_ms": statistics.mean(times),
            "min_response_time_ms": min(times),
            "max_response_time_ms": max(times),
            "median_response_time_ms": statistics.median(times),
            "p90_response_time_ms": sorted(times)[int(len(times) * 0.9)],
            "status_codes": {code: status_codes.count(code) for code in set(status_codes)}
        }
        
        self.results.append(result)
        return result
    
    def run_tests(self):
        """Run all performance tests."""
        print("=== Starting performance measurements ===\n")
        
        # GET request
        print("1. Testing simple GET request (parking-lots)...")
        self.measure_endpoint("GET", "/parking-lots", name="GET /parking-lots (unauthenticated)")
        
        # Authenticated test
        print("\n2. Logging in...")
        if not self.login():
            print("Login failed, cannot run authenticated tests.")
            return
            
        print("3. Testing authenticated endpoint (profile)...")
        self.measure_endpoint("GET", "/profile", name="GET /profile (authenticated)")
        
        # POST request
        print("\n4. Testing complex POST request (start parking session)...")
        lots = self.session.get(f"{BASE_URL}/parking-lots").json()
        if lots and len(lots) > 0:
            lot_id = list(lots.keys())[0]
            self.measure_endpoint(
                "POST", 
                f"/parking-lots/{lot_id}/sessions/start",
                json_data={"license_plate": "TEST123"},
                name=f"POST /parking-lots/{{id}}/sessions/start"
            )
        else:
            print("No parking lots available for testing.")
    
    def save_results(self, filename: str = "performance_results.json"):
        """Save performance results to a JSON file."""
        with open(filename, 'w') as f:
            json.dump({
                "test_run": datetime.now().isoformat(),
                "results": self.results
            }, f, indent=2)
        print(f"\nResults saved to {filename}")

if __name__ == "__main__":
    tester = PerformanceTester()
    tester.run_tests()
    tester.save_results()
    
    print("\n=== The test results! ===")
    for result in tester.results:
        print(f"\n{result['endpoint']}:")
        print(f"  - Average response time: {result['avg_response_time_ms']:.2f} ms")
        print(f"  - Fastest: {result['min_response_time_ms']:.2f} ms")
        print(f"  - Slowest: {result['max_response_time_ms']:.2f} ms")
        print(f"  - Successful requests: {result['successful_requests']}/{result['request_count']}")
        print(f"  - Status codes: {', '.join(f'{k} ({v}x)' for k, v in result['status_codes'].items())}")
