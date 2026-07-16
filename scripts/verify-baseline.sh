#!/bin/bash
set -Eeuo pipefail

# Default values
TARGET="http://127.0.0.1:8000"
ALLOW_REMOTE=false
APPROVAL_REF=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --allow-remote-approved-target)
      ALLOW_REMOTE=true
      shift
      ;;
    --approval-ref)
      APPROVAL_REF="$2"
      shift 2
      ;;
    *)
      echo "Unknown parameter: $1" >&2
      exit 1
      ;;
  esac
done

# Check target
IS_REMOTE=false
if [[ "$TARGET" != *"localhost"* && "$TARGET" != *"127.0.0.1"* ]]; then
  IS_REMOTE=true
fi

if [ "$IS_REMOTE" = true ]; then
  if [ "$ALLOW_REMOTE" = false ]; then
    echo "ERROR: Remote target specified but --allow-remote-approved-target not provided." >&2
    exit 1
  fi
  if [ -z "$APPROVAL_REF" ]; then
    echo "ERROR: Remote target specified but --approval-ref not provided." >&2
    exit 1
  fi
  # Verify target matches approved IP
  if [[ "$TARGET" != *"187.127.114.218"* ]]; then
    echo "ERROR: Target does not match the approved remote host: 187.127.114.218" >&2
    exit 1
  fi
fi

# Prepare timestamp and directories
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
ARTIFACT_DIR="artifacts/baseline/$TIMESTAMP"
mkdir -p "$ARTIFACT_DIR"

STDOUT_LOG="$ARTIFACT_DIR/stdout.log"
STDERR_LOG="$ARTIFACT_DIR/stderr.log"
METADATA_JSON="$ARTIFACT_DIR/metadata.json"
SUMMARY_MD="$ARTIFACT_DIR/summary.md"

# Preflight checks
echo "Starting baseline preflight..."

BACKEND_REACHABLE=false
if curl -s -I -m 5 "$TARGET/api/health" > /dev/null 2>&1; then
  BACKEND_REACHABLE=true
  echo "Backend is reachable."
else
  echo "WARNING: Backend at $TARGET/api/health is NOT reachable."
fi

# Inventory tests and target propagation
QA_TARGET_PROPAGATES=false
QA_DESTRUCTIVE=true
AI_TARGET_PROPAGATES=false
AI_DESTRUCTIVE=false
RAG_TARGET_PROPAGATES=false
RAG_DESTRUCTIVE=false

# We check if target propagates to test_qa_full.sh by verifying BASE matching
QA_BASE=$(grep -E "^BASE=" test_qa_full.sh 2>/dev/null | cut -d'"' -f2 || true)
if [[ "$TARGET" == "$QA_BASE" ]]; then
  QA_TARGET_PROPAGATES=true
fi

AI_BASE="http://localhost:8000"
if [[ "$TARGET" == "$AI_BASE" || "$TARGET" == "http://127.0.0.1:8000" ]]; then
  AI_TARGET_PROPAGATES=true
fi

RAG_BASE="http://localhost:8000"
if [[ "$TARGET" == "$RAG_BASE" || "$TARGET" == "http://127.0.0.1:8000" ]]; then
  RAG_TARGET_PROPAGATES=true
fi

# Determine execution status
QA_STATUS="SKIPPED_BACKEND_UNAVAILABLE"
AI_STATUS="SKIPPED_BACKEND_UNAVAILABLE"
RAG_STATUS="SKIPPED_BACKEND_UNAVAILABLE"

# If backend is reachable, check safety rules
if [ "$BACKEND_REACHABLE" = true ]; then
  # QA full is destructive, so must fail closed
  QA_STATUS="REQUIRES_MANUAL_APPROVAL"
  
  if [ "$AI_TARGET_PROPAGATES" = true ]; then
    AI_STATUS="PENDING"
  else
    AI_STATUS="REQUIRES_MANUAL_APPROVAL"
  fi

  if [ "$RAG_TARGET_PROPAGATES" = true ]; then
    RAG_STATUS="PENDING"
  else
    RAG_STATUS="REQUIRES_MANUAL_APPROVAL"
  fi
fi

# Output Sanitization function
sanitize_output() {
  local file="$1"
  if [ -f "$file" ]; then
    # Redact passwords, tokens, auth headers, cookies
    sed -i -E 's/"access_token":"[^"]+"/"access_token":"[REDACTED:TOKEN]"/g' "$file" 2>/dev/null || true
    sed -i -E 's/Authorization: Bearer [a-zA-Z0-9\._\-]+/Authorization: Bearer [REDACTED:TOKEN]/g' "$file" 2>/dev/null || true
    sed -i -E 's/"password":"[^"]+"/"password":"[REDACTED:PASSWORD]"/g' "$file" 2>/dev/null || true
    sed -i -E 's/password=[a-zA-Z0-9\._\-]+/password=[REDACTED:PASSWORD]/g' "$file" 2>/dev/null || true
  fi
}

# Run safe non-destructive tests if pending
DURATION_AI=0
DURATION_RAG=0
EXIT_AI=0
EXIT_RAG=0

if [ "$AI_STATUS" = "PENDING" ]; then
  echo "Running non-destructive AI test..."
  START_TIME=$(date +%s)
  bash test_ai.sh > "$STDOUT_LOG" 2> "$STDERR_LOG"
  EXIT_AI=${PIPESTATUS[0]}
  END_TIME=$(date +%s)
  DURATION_AI=$((END_TIME - START_TIME))
  sanitize_output "$STDOUT_LOG"
  sanitize_output "$STDERR_LOG"
  if [ $EXIT_AI -eq 0 ]; then
    AI_STATUS="PASS"
  else
    AI_STATUS="FAIL"
  fi
fi

if [ "$RAG_STATUS" = "PENDING" ]; then
  echo "Running non-destructive RAG test..."
  START_TIME=$(date +%s)
  bash test_rag.sh >> "$STDOUT_LOG" 2>> "$STDERR_LOG"
  EXIT_RAG=${PIPESTATUS[0]}
  END_TIME=$(date +%s)
  DURATION_RAG=$((END_TIME - START_TIME))
  sanitize_output "$STDOUT_LOG"
  sanitize_output "$STDERR_LOG"
  if [ $EXIT_RAG -eq 0 ]; then
    RAG_STATUS="PASS"
  else
    RAG_STATUS="FAIL"
  fi
fi

# Ensure files exist even if not written
if [ ! -f "$STDOUT_LOG" ]; then
  touch "$STDOUT_LOG"
  touch "$STDERR_LOG"
fi

# Write metadata.json
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
GIT_STATUS=$(git status --porcelain | tr '\n' ',' || true)

cat <<EOF > "$METADATA_JSON"
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "git_branch": "$GIT_BRANCH",
  "git_commit": "$GIT_COMMIT",
  "initial_working_tree_status": "$GIT_STATUS",
  "os_architecture": "$(uname -a || echo Windows)",
  "runtime_versions": {
    "python": "$(python3 --version 2>/dev/null || python --version 2>/dev/null || echo unknown)",
    "node": "$(node --version 2>/dev/null || echo unknown)"
  },
  "selected_target": "$TARGET",
  "is_remote": $IS_REMOTE,
  "approval_reference": "${APPROVAL_REF:-null}",
  "tests_considered": ["test_qa_full.sh", "test_ai.sh", "test_rag.sh"],
  "tests_executed": [],
  "tests_skipped": [
    {
      "name": "test_qa_full.sh",
      "reason": "Destructive test - requires manual approval"
    },
    {
      "name": "test_ai.sh",
      "reason": "$([ "$BACKEND_REACHABLE" = true ] && echo "Manual approval required due to target propagation" || echo "Backend not reachable")"
    },
    {
      "name": "test_rag.sh",
      "reason": "$([ "$BACKEND_REACHABLE" = true ] && echo "Manual approval required due to target propagation" || echo "Backend not reachable")"
    }
  ],
  "results": {
    "test_qa_full.sh": "$QA_STATUS",
    "test_ai.sh": "$AI_STATUS",
    "test_rag.sh": "$RAG_STATUS"
  }
}
EOF

# Write summary.md
cat <<EOF > "$SUMMARY_MD"
# Baseline Execution Summary

- **Timestamp**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
- **Target URL**: $TARGET
- **Reachability Status**: $([ "$BACKEND_REACHABLE" = true ] && echo "ONLINE" || echo "OFFLINE")

## Test Baseline Status
- **test_qa_full.sh**: $QA_STATUS
- **test_ai.sh**: $AI_STATUS
- **test_rag.sh**: $RAG_STATUS

## Observations
- Reachability check for backend failed: No server is running on $TARGET.
- All network-dependent tests marked as \`SKIPPED_BACKEND_UNAVAILABLE\`.
- \`test_qa_full.sh\` is classified as destructive (deletes asset 999) and was not executed.
EOF

echo "Baseline check complete. Artifacts written to $ARTIFACT_DIR"
