import requests
import json

base = "http://localhost:8000"

# Test SPEAK
print("=== Testing SPEAK ===")
try:
    r = requests.post(f"{base}/api/speak/chat", json={"message": "What is our current ransomware exposure?"}, timeout=90)
    print(f"Status: {r.status_code}")
    print(f"Response: {json.dumps(r.json(), indent=2)[:500]}")
except Exception as e:
    print(f"Error: {e}")

# Test SPOTLIGHT
print("\n=== Testing SPOTLIGHT ===")
try:
    r = requests.post(f"{base}/api/spotlight/generate", timeout=90)
    print(f"Status: {r.status_code}")
    print(f"Response: {json.dumps(r.json(), indent=2)[:500]}")
except Exception as e:
    print(f"Error: {e}")
