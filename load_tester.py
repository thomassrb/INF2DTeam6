import requests
import threading
import time
from datetime import datetime, timedelta

# Endpoint moet je aanpassen naar degene die je wilt testen, dus bijv parking-lots
API_ENDPOINT = "http://localhost:8000/reservations"
LOGIN_URL = "http://localhost:8000/login"
NUM_CONCURRENT_REQUESTS = 50 # hier de amount die je wilt testen, vanuit de CTO is het 50!

def login_and_get_token(thread_id):
    username = f"testuser_{thread_id}"
    password = "password123"
    login_data = {"username": username, "password": password}
    try:
        response = requests.post(LOGIN_URL, json=login_data)
        if response.status_code == 200:
            return response.json().get("session_token"), username
        else:
            print(f"Thread {thread_id}: Login Failed (Status: {response.status_code})")
            return None, None
    except requests.exceptions.RequestException as e:
        print(f"Thread {thread_id}: Login Error - {e}")
        return None, None

def send_request(thread_id, results):
    session_token, username = login_and_get_token(thread_id)
    if not session_token:
        results.append((False, 0))
        return

    try:
        start_time_reservation = datetime.now() + timedelta(days=1, hours=thread_id)
        end_time_reservation = start_time_reservation + timedelta(hours=2)

        reservation_data = {
            "parkinglot": "1", # Assuming parking lot ID 1 exists
            "user": username,
            "licenseplate": f"ABC{thread_id:03d}", # Unique license plate
            "start_time": start_time_reservation.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": end_time_reservation.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        headers = {"Authorization": f"Bearer {session_token}"}
        
        start_time = time.time()
        response = requests.post(API_ENDPOINT, json=reservation_data, headers=headers)
        end_time = time.time()
        duration = (end_time - start_time) * 1000

        if response.status_code == 201:
            results.append((True, duration))
            print(f"Thread {thread_id}: Success (Reservation Created, Status: {response.status_code}, Time: {duration:.2f} ms)")
        elif response.status_code in [400, 403, 404, 409]: # Consider these as handled errors
            results.append((True, duration))
            print(f"Thread {thread_id}: Success (Reservation Failed - Status: {response.status_code}, Time: {duration:.2f} ms)")
        else:
            results.append((False, duration))
            print(f"Thread {thread_id}: Failed (Status: {response.status_code}, Time: {duration:.2f} ms)")
    except requests.exceptions.RequestException as e:
        results.append((False, 0))
        print(f"Thread {thread_id}: Reservation Error - {e}")

def main():
    print(f"Starting load test with {NUM_CONCURRENT_REQUESTS} concurrent requests to {API_ENDPOINT}")
    threads = []
    results = []

    start_test_time = time.time()

    for i in range(NUM_CONCURRENT_REQUESTS):
        thread = threading.Thread(target=send_request, args=(i, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_test_time = time.time()
    total_test_duration = (end_test_time - start_test_time) * 1000

    successful_requests = [r for r, _ in results if r]
    failed_requests = [r for r, _ in results if not r]
    response_times = [d for r, d in results if r]

    print("\n--- Load Test Results ---")
    print(f"Total Requests: {len(results)}")
    print(f"Successful Requests: {len(successful_requests)}")
    print(f"Failed Requests: {len(failed_requests)}")
    print(f"Total Test Duration: {total_test_duration:.2f} ms")
    
    if response_times:
        avg_response_time = sum(response_times) / len(response_times)
        print(f"Average Successful Response Time: {avg_response_time:.2f} ms")
    else:
        print("No successful requests to calculate average response time.")

    if len(successful_requests) >= NUM_CONCURRENT_REQUESTS:
        print("STATUS: PASSED - Achieved at least 50 concurrent successful requests.")
    else:
        print("STATUS: FAILED - Did NOT achieve at least 50 concurrent successful requests.")

if __name__ == "__main__":
    main()
