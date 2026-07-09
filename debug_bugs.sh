#!/bin/bash
BASE="http://127.0.0.1:8000"

get_token() {
    curl -s -X POST "$BASE/api/auth/login" \
      -H 'Content-Type: application/json' \
      -d "{\"email\":\"$1\",\"password\":\"demo\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null
}

echo "=== Getting tokens ==="
TOKEN_V=$(get_token "viewer@tempris.com")
TOKEN_SA=$(get_token "sherie@tempris.com")

echo ""
echo "=== Bug 1: Policy Update 500 (Viewer should get 403) ==="
curl -sv -X PUT "$BASE/api/grc/policies/iso42001_ai_policy" \
  -H "Authorization: Bearer $TOKEN_V" \
  -H 'Content-Type: application/json' \
  -d '{"content":"test"}' 2>&1 | tail -5

echo ""
echo "=== Bug 2: Path Traversal 500 ==="
echo 'test content' > /tmp/test_evidence.pdf
curl -sv -X POST "$BASE/api/grc/evidence/A.2.2" \
  -H "Authorization: Bearer $TOKEN_SA" \
  -F "file=@/tmp/test_evidence.pdf;filename=../../etc/passwd.pdf" 2>&1 | tail -5

echo ""
echo "=== Bug 3: Audit Hash Chain ==="
curl -s "$BASE/api/audit/verify" -H "Authorization: Bearer $TOKEN_SA" | python3 -m json.tool 2>&1

echo ""
echo "=== Docker logs (last errors) ==="
docker logs tempris_backend 2>&1 | grep -i "error\|traceback\|exception" | tail -10
