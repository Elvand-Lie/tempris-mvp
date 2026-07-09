#!/bin/bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"sherie@tempris.com","password":"demo"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

echo "=== 1. RAG Stats ==="
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/rag/stats
echo ""

echo ""
echo "=== 2. Semantic Search: AI Hallucination Policy ==="
curl -s -X POST http://localhost:8000/api/rag/search \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "What is the policy for AI hallucination?", "n_results": 3}'
echo ""

echo ""
echo "=== 3. Semantic Search: Ransomware CVEs ==="
curl -s -X POST http://localhost:8000/api/rag/search \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "Which CVEs are linked to ransomware campaigns?", "n_results": 3}'
echo ""

echo ""
echo "=== 4. SPEAK with RAG: ISO 42001 question ==="
curl -s -X POST http://localhost:8000/api/speak/chat \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"message": "What does our ISO 42001 policy say about third-party AI providers?"}'
echo ""
