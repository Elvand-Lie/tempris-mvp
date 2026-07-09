#!/bin/bash
# Tempris Daily Backup Script
# Backs up PostgreSQL database with 7-day retention
# Install: crontab -e → 0 3 * * * /home/tempris/app/backup.sh >> /home/tempris/app/backup.log 2>&1

set -euo pipefail

BACKUP_DIR="/home/tempris/backups"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/tempris_db_${DATE}.sql.gz"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')]"

mkdir -p "${BACKUP_DIR}"

echo "${LOG_PREFIX} Starting backup..."

# Get Postgres container ID
PG_CONTAINER=$(docker ps --filter name=postgres --format '{{.ID}}' | head -1)

if [ -z "${PG_CONTAINER}" ]; then
    echo "${LOG_PREFIX} ERROR: PostgreSQL container not found!"
    exit 1
fi

# Dump database
docker exec "${PG_CONTAINER}" pg_dump -U tempris tempris_db | gzip > "${BACKUP_FILE}"

# Verify backup integrity
if gunzip -t "${BACKUP_FILE}" 2>/dev/null; then
    SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
    echo "${LOG_PREFIX} SUCCESS: Backup created (${SIZE}): ${BACKUP_FILE}"
else
    echo "${LOG_PREFIX} ERROR: Backup file is corrupt!"
    rm -f "${BACKUP_FILE}"
    exit 1
fi

# Cleanup old backups (keep last N days)
DELETED=$(find "${BACKUP_DIR}" -name "tempris_db_*.sql.gz" -mtime +${RETENTION_DAYS} -print -delete | wc -l)
if [ "${DELETED}" -gt 0 ]; then
    echo "${LOG_PREFIX} Cleaned up ${DELETED} old backup(s)"
fi

echo "${LOG_PREFIX} Backup complete. Active backups:"
ls -lh "${BACKUP_DIR}"/tempris_db_*.sql.gz 2>/dev/null | tail -7
