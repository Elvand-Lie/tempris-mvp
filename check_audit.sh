#!/bin/bash
# Get token
BODY='{"email":"sherie@tempris.com","password":"demo"}'
ACCESS=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' -d "$BODY" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# Save audit log to file, then parse
curl -s http://127.0.0.1:8000/api/audit/log -H "Authorization: Bearer $ACCESS" > /tmp/audit_out.json
echo "Audit response size: $(wc -c < /tmp/audit_out.json) bytes"
echo "First 200 chars: $(head -c 200 /tmp/audit_out.json)"
echo ""

# Parse if valid JSON
python3 << 'PYEOF'
import json
with open("/tmp/audit_out.json") as f:
    content = f.read()
if not content.strip():
    print("ERROR: Empty response from audit endpoint")
else:
    d = json.loads(content)
    print(f"Total audit entries: {len(d)}")
    print("Last 5 entries:")
    for e in d[-5:]:
        print(f"  {e.get('timestamp','?')} | user={e.get('user','?')} | action={e.get('action','?')} | module={e.get('module','?')}")
PYEOF

echo ""
echo "=== HASH CHAIN ==="
curl -s 'http://127.0.0.1:8000/api/audit/verify' -H "Authorization: Bearer $ACCESS" > /tmp/verify_out.json
python3 << 'PYEOF'
import json
with open("/tmp/verify_out.json") as f:
    content = f.read()
if not content.strip():
    print("ERROR: Empty response from verify endpoint")
else:
    d = json.loads(content)
    print(f"Status: {d.get('status','?')} | Records: {d.get('records','?')} | Intact: {d.get('intact','?')} | Mismatches: {d.get('mismatches','?')}")
PYEOF
