#!/bin/bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"sherie@tempris.com","password":"demo"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

echo "=== Get Policy ==="
curl -s -w '\nHTTP_CODE:%{http_code}\n' -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/grc/policies/iso42001
