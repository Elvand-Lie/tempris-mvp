import requests
import json

base = "http://localhost:8000"

# Authenticate first
print("=== Login ===")
try:
    r = requests.post(f"{base}/api/auth/login", json={"email": "sherie@tempris.com", "password": "demo"}, timeout=10)
    r.raise_for_status()
    token = r.json()["access_token"]
    print(f"Logged in as {r.json()['user']['name']} ({r.json()['user']['role']})")
except Exception as e:
    print(f"Login failed: {e}")
    exit(1)

headers = {"Authorization": f"Bearer {token}"}

# Test SPEAK
print("\n=== Testing SPEAK ===")
try:
    r = requests.post(f"{base}/api/speak/chat", json={"message": "What is our current ransomware exposure?"}, headers=headers, timeout=90)
    print(f"Status: {r.status_code}")
    print(f"Response: {json.dumps(r.json(), indent=2)[:500]}")
except Exception as e:
    print(f"Error: {e}")

# Test SPOTLIGHT
print("\n=== Testing SPOTLIGHT ===")
try:
    r = requests.post(f"{base}/api/spotlight/generate", json={"report_type": "executive"}, headers=headers, timeout=90)
    print(f"Status: {r.status_code}")
    print(f"Response: {json.dumps(r.json(), indent=2)[:500]}")
except Exception as e:
    print(f"Error: {e}")
