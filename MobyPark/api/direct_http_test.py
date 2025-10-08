import http.client
import json

HOST = 'localhost'
PORT = 8000
PATH = '/profile'

def test_direct_http():
    print(f"\nAttempting direct HTTP GET to {HOST}:{PORT}{PATH}")
    try:
        conn = http.client.HTTPConnection(HOST, PORT)
        conn.request("GET", PATH)
        response = conn.getresponse()
        
        print(f"--- Direct HTTP Response ---")
        print(f"Status: {response.status}")
        print(f"Reason: {response.reason}")
        print("Headers:")
        for header, value in response.getheaders():
            print(f"  {header}: {value}")
        
        data = response.read().decode()
        print("Body:")
        try:
            print(json.dumps(json.loads(data), indent=2))
        except json.JSONDecodeError:
            print(data)
            
        conn.close()
        
    except Exception as e:
        print(f"Error during direct HTTP request: {e}")

if __name__ == "__main__":
    test_direct_http()
