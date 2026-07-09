#!/bin/bash
echo "=== 1. INSTANCE ISOLATION ==="
echo "Hostname: $(hostname)"
echo "IP: $(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}')"
echo "No domain name configured (bare IP only)"
echo ""

echo "=== 2. CREDENTIALS & DATA CHECK ==="
docker exec tempris_backend env 2>/dev/null | grep -iE 'key|secret|password' | sed 's/=.*/=***REDACTED***/'
echo ""

echo "=== 3. TACF AUDIT TRAIL ==="
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"sherie@tempris.com","password":"demo"}')
ACCESS=$(echo "$TOKEN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s http://127.0.0.1:8000/api/audit/log \
  -H "Authorization: Bearer $ACCESS" | python3 << 'PYEOF'
import sys, json
d = json.load(sys.stdin)
print(f"Total audit entries: {len(d)}")
print("Last 5 entries:")
for e in d[-5:]:
    ts = e.get("timestamp", "?")
    user = e.get("user", "?")
    action = e.get("action", "?")
    module = e.get("module", "?")
    ip = e.get("ip", "?")
    print(f"  {ts} | user={user} | action={action} | module={module} | ip={ip}")
PYEOF

echo ""
echo "-- Hash chain integrity --"
curl -s "http://127.0.0.1:8000/api/audit/verify" \
  -H "Authorization: Bearer $ACCESS" | python3 << 'PYEOF'
import sys, json
d = json.load(sys.stdin)
status = d.get("status", "?")
records = d.get("records", "?")
intact = d.get("intact", "?")
mismatches = d.get("mismatches", "?")
print(f"Status: {status} | Records: {records} | Intact: {intact} | Mismatches: {mismatches}")
PYEOF
