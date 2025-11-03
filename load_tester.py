import requests
import threading
import time

# Endpoint moet je aanpassen naar degene die je wilt testen, dus bijv parking-lots
API_ENDPOINT = "http://localhost:8000/register"
NUM_CONCURRENT_REQUESTS = 50 # hier de amount die je wilt testen, vanuit de CTO is het 50!

def send_request(thread_id, results):
    try:
        start_time = time.time()
        # Data == voor de post requests anders krijg je standaard alles failed..
        data = {
            "username": f"testuser_{thread_id}",
            "password": "password123",
            "name": f"Test User {thread_id}",
            "phone": f"06123456{thread_id:02d}", # Unique phone number
            "email": f"testuser_{thread_id}@example.com", # Unique email
            "birth_year": "2000"
        }
        response = requests.post(API_ENDPOINT, json=data)
        end_time = time.time()
        duration = (end_time - start_time) * 1000
        if response.status_code == 201:
            results.append((True, duration))
            print(f"Thread {thread_id}: Success (Created, Status: {response.status_code}, Time: {duration:.2f} ms)")
        elif response.status_code == 409:
            results.append((True, duration))
            print(f"Thread {thread_id}: Success (Conflict, Status: {response.status_code}, Time: {duration:.2f} ms)")
        elif response.status_code == 200:
            results.append((True, duration))
            print(f"Thread {thread_id}: Success (OKE, Status: {response.status_code}, Time: {duration:.2f} ms)")
        else:
            results.append((False, duration))
            print(f"Thread {thread_id}: Failed (Status: {response.status_code}, Time: {duration:.2f} ms)")
    except requests.exceptions.RequestException as e:
        results.append((False, 0))
        print(f"Thread {thread_id}: Error - {e}")

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
