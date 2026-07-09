#!/bin/bash
# Test SPEAK and SPOTLIGHT full data access

TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"sherie@tempris.com","password":"demo"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

echo "=== TOKEN obtained ==="

echo ""
echo "=== Test 1: SPEAK - Assets ==="
curl -s -X POST http://localhost:8000/api/speak/chat \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"message":"What assets do we have in our inventory?"}' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["response"][:400]); print("Sources:", d["sources"])'

echo ""
echo "=== Test 2: SPEAK - Compliance ==="
curl -s -X POST http://localhost:8000/api/speak/chat \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"message":"What is our compliance status across frameworks?"}' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["response"][:400]); print("Sources:", d["sources"])'

echo ""
echo "=== Test 3: SPEAK - STRIKE ==="
curl -s -X POST http://localhost:8000/api/speak/chat \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"message":"Show me STRIKE simulation results"}' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["response"][:400]); print("Sources:", d["sources"])'

echo ""
echo "=== Test 4: SPOTLIGHT - Executive Report ==="
curl -s -X POST http://localhost:8000/api/spotlight/generate \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"report_type":"executive"}' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["ai_narrative"][:500]); print("Model:", d["metadata"]["model"])'

echo ""
echo "=== All tests complete ==="
