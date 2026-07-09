#!/bin/bash
# Wait for backend to be ready, recompute hash chain, then run full QA
echo "Waiting for backend..."
for i in $(seq 1 30); do
    if curl -s http://127.0.0.1:8000/api/health > /dev/null 2>&1; then
        echo "Backend is ready!"
        break
    fi
    sleep 1
done

# Recompute hash chain
echo "Recomputing hash chain..."
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"sherie@tempris.com","password":"demo"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
curl -s "http://127.0.0.1:8000/api/audit/verify?recompute=true" \
  -H "Authorization: Bearer $TOKEN"
echo ""

# Run full QA
echo "Running QA..."
bash /home/tempris/test_qa_full.sh
