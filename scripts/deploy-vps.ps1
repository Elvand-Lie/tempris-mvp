[CmdletBinding()]
param(
    [switch]$Deploy,
    [string]$VpsHost = "187.127.114.218",
    [string]$SshUser = "tempris",
    [string]$RemoteRoot = "/home/tempris",
    [string]$PostgresContainer = "tempris-app-postgres-1"
)

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ssh = "$env:WINDIR\System32\OpenSSH\ssh.exe"
$scp = "$env:WINDIR\System32\OpenSSH\scp.exe"

function Invoke-Remote([string]$Command) {
    & $ssh -o BatchMode=yes -o ConnectTimeout=15 "$SshUser@$VpsHost" $Command
    if ($LASTEXITCODE -ne 0) { throw "Remote command failed." }
}

Push-Location $repoRoot
try {
    if (git status --porcelain --untracked-files=no) {
        throw "Refusing to release: commit or stash tracked worktree changes first."
    }
    $commit = (git rev-parse HEAD).Trim()
    git diff --check
    if ($LASTEXITCODE -ne 0) { throw "git diff --check failed." }

    $compose = "$RemoteRoot/app/deploy/docker-compose.prod.yml"
    $preflight = "test -f '$compose' -a -f '$RemoteRoot/app/deploy/.env' && command -v rsync >/dev/null && docker compose -f '$compose' config -q && docker ps --format '{{.Names}}' | grep -qx tempris_backend && docker ps --format '{{.Names}}' | grep -qx '$PostgresContainer'"
    Invoke-Remote $preflight
    if (-not $Deploy) {
        Write-Host "Preflight passed for $SshUser@$VpsHost. Re-run with -Deploy to release commit $commit." -ForegroundColor Green
        return
    }

    $releaseId = "tempris-$commit-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $archive = Join-Path $env:TEMP "$releaseId.tar.gz"
    try {
        git archive --format=tar.gz --output=$archive $commit
        if ($LASTEXITCODE -ne 0) { throw "Git archive creation failed." }
        $hash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $remoteArchive = "/tmp/$releaseId.tar.gz"
        & $scp -o BatchMode=yes $archive "$SshUser@$VpsHost`:$remoteArchive"
        if ($LASTEXITCODE -ne 0) { throw "Archive upload failed." }
        Invoke-Remote "test `$(sha256sum '$remoteArchive' | awk '{print `$1}') = '$hash'"

        $remoteScript = @"
set -euo pipefail
root='$RemoteRoot'
release='$releaseId'
archive='$remoteArchive'
pg_container='$PostgresContainer'
source_backup="`$root/backups/releases/`$release.tar.gz"
db_backup="`$root/backups/database/`$release.dump"
report_backup="`$root/backups/reports/`$release.tar.gz"
migration_report="`$root/backups/migrations/`$release-migration-008.json"
migration_009_report="`$root/backups/migrations/`$release-migration-009.txt"
migration_010_report="`$root/backups/migrations/`$release-migration-010.txt"
migration_011_report="`$root/backups/migrations/`$release-migration-011.txt"
migration_012_report="`$root/backups/migrations/`$release-migration-012.txt"
migration_013_report="`$root/backups/migrations/`$release-migration-013.txt"
stage="`$(mktemp -d)"
restore_stage=''
source_changed=0
db_changed=0

rollback() {
  status=`$?
  set +e
  echo "Release failed; restoring the verified database, report artifacts, source, and frontend." >&2
  if [ -s "`$report_backup" ]; then
    docker cp "`$report_backup" "tempris_backend:/tmp/`$release.reports.rollback.tar.gz"
    docker exec -u 0 -e RELEASE="`$release" tempris_backend sh -lc 'rm -rf /app/data/reports && mkdir -p /app/data && tar -C /app/data -xzf /tmp/`$RELEASE.reports.rollback.tar.gz && rm -f /tmp/`$RELEASE.reports.rollback.tar.gz' || echo "ERROR: automatic report-artifact restoration failed; use `$(printf %q "`$report_backup") manually." >&2
  fi
  if [ "`$db_changed" -eq 1 ] && [ -s "`$db_backup" ]; then
    docker stop tempris_backend >/dev/null 2>&1
    docker cp "`$db_backup" "`$pg_container:/tmp/`$release.rollback.dump"
    docker exec -e RELEASE="`$release" "`$pg_container" sh -lc 'pg_restore -U "`$POSTGRES_USER" -d "`$POSTGRES_DB" --clean --if-exists --no-owner --no-privileges /tmp/`$RELEASE.rollback.dump' || echo "ERROR: automatic database restoration failed; use `$(printf %q "`$db_backup") manually." >&2
    docker exec "`$pg_container" rm -f "/tmp/`$release.rollback.dump"
  fi
  if [ "`$source_changed" -eq 1 ] && [ -s "`$source_backup" ]; then
    restore_stage="`$(mktemp -d)"
    tar -C "`$restore_stage" -xzf "`$source_backup"
    rsync -a --delete --exclude='deploy/.env' --exclude='freellmapi/.env' --exclude='backend/data/' "`$restore_stage/app/" "`$root/app/"
  fi
  if [ "`$source_changed" -eq 1 ] || [ "`$db_changed" -eq 1 ]; then
    cd "`$root/app/deploy"
    docker compose -f docker-compose.prod.yml up -d --build || echo "ERROR: automatic application restoration failed." >&2
  fi
  rm -rf "`$stage" "`$restore_stage" "`$archive"
  exit "`$status"
}
trap rollback ERR

mkdir -p "`$(dirname "`$source_backup")" "`$(dirname "`$db_backup")" "`$(dirname "`$report_backup")" "`$(dirname "`$migration_report")" "`$(dirname "`$migration_009_report")" "`$(dirname "`$migration_010_report")" "`$(dirname "`$migration_011_report")" "`$(dirname "`$migration_012_report")" "`$(dirname "`$migration_013_report")"
tar -C "`$root" -czf "`$source_backup" --exclude='app/deploy/.env' --exclude='app/freellmapi/.env' --exclude='app/backend/data' app
tar -tzf "`$source_backup" >/dev/null
tar -C "`$stage" -xzf "`$archive"
docker exec -u 0 -e RELEASE="`$release" tempris_backend sh -lc 'mkdir -p /app/data/reports && tar -C /app/data -czf /tmp/`$RELEASE.reports.tar.gz reports && tar -tzf /tmp/`$RELEASE.reports.tar.gz >/dev/null'
docker cp "tempris_backend:/tmp/`$release.reports.tar.gz" "`$report_backup"
docker exec -u 0 -e RELEASE="`$release" tempris_backend sh -lc 'rm -f /tmp/`$RELEASE.reports.tar.gz'
test -s "`$report_backup"
tar -tzf "`$report_backup" >/dev/null

# Product documentation is maintained at repository-root docs/product but the
# production Compose mount expects it beneath app/docs.
if [ -d "`$stage/docs/product" ]; then
  rm -rf "`$stage/app/docs/product"
  mkdir -p "`$stage/app/docs/product"
  cp -a "`$stage/docs/product/." "`$stage/app/docs/product/"
fi

docker exec -e RELEASE="`$release" "`$pg_container" sh -lc 'pg_dump -U "`$POSTGRES_USER" -d "`$POSTGRES_DB" -Fc -f /tmp/`$RELEASE.dump && pg_restore --list /tmp/`$RELEASE.dump >/dev/null'
docker cp "`$pg_container:/tmp/`$release.dump" "`$db_backup"
docker exec "`$pg_container" rm -f "/tmp/`$release.dump"
test -s "`$db_backup"
db_changed=1

docker cp "`$stage/scripts/migrations/006_add_sss_sub_class.py" tempris_backend:/tmp/006_add_sss_sub_class.py
docker cp "`$stage/scripts/migrations/007_create_tenant_registry.py" tempris_backend:/tmp/007_create_tenant_registry.py
docker cp "`$db_backup" "tempris_backend:/tmp/`$release.dump"
docker exec tempris_backend python /tmp/006_add_sss_sub_class.py --database-url-env --backup-file "/tmp/`$release.dump" --externally-verified-backup
docker exec tempris_backend python /tmp/007_create_tenant_registry.py --database-url-env --backup-file "/tmp/`$release.dump" --externally-verified-backup
docker exec -u 0 tempris_backend rm -f /tmp/006_add_sss_sub_class.py /tmp/007_create_tenant_registry.py "/tmp/`$release.dump"

# Migration 008 imports the new canonical models. Run it in the existing
# backend image with the staged backend source mounted read-only, before the
# production source or process is replaced.
backend_image="`$(docker inspect -f '{{.Image}}' tempris_backend)"
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -v "`$db_backup:/backup.dump:ro" \
  -v "`$(dirname "`$migration_report"):/migration-report" \
  -w /staged "`$backend_image" \
  python /migrations/008_canonical_posture_and_operations.py \
    --database-url-env --backup-file /backup.dump --externally-verified-backup \
    --report-file "/migration-report/`$(basename "`$migration_report")"

# 009 is additive: it seeds the server-managed ISO/IEC 42001 catalogue and
# preserves legacy SOP state without guessing policy-control links.
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/009_canonical_grc_framework.py --database-url-env > "`$migration_009_report"
test -s "`$migration_009_report"

# 010 only adds auditable CVE-context storage. It never promotes legacy links.
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/010_live_cve_tes_context.py --database-url-env > "`$migration_010_report"
test -s "`$migration_010_report"

# 011 creates the canonical vulnerability spine tables
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/011_canonical_vulnerability_spine.py --database-url-env > "`$migration_011_report"
test -s "`$migration_011_report"

# 012 adds canonical_cve_id linkage to findings
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/012_finding_canonical_cve_linkage.py --database-url-env > "`$migration_012_report"
test -s "`$migration_012_report"

# 013 adds asset_scan_authorizations and scan_jobs target provenance
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/013_asset_scan_authorizations.py --database-url-env --apply > "`$migration_013_report"
test -s "`$migration_013_report"

source_changed=1
rsync -a --delete --exclude='deploy/.env' --exclude='freellmapi/.env' --exclude='backend/data/' "`$stage/app/" "`$root/app/"
docker cp "`$stage/app/backend/data/v62_debrief_findings.json" tempris_backend:/app/data/v62_debrief_findings.json

cd "`$root/app/deploy"
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml exec -T backend python -c 'from services.database import SessionLocal; from models import Finding; from scripts.seed_findings import seed_v62_debrief_findings; db = SessionLocal(); existing = {row[0] for row in db.query(Finding.id).all()}; seed_v62_debrief_findings(db, existing); db.commit(); db.close()'
curl --fail --silent --show-error --retry 10 --retry-delay 3 --max-time 20 http://127.0.0.1:8000/api/health >/dev/null
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/008_canonical_posture_and_operations.py --database-url-env --dry-run >/dev/null
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/009_canonical_grc_framework.py --database-url-env --dry-run >/dev/null
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/010_live_cve_tes_context.py --database-url-env --dry-run >/dev/null
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/011_canonical_vulnerability_spine.py --database-url-env --dry-run >/dev/null
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/012_finding_canonical_cve_linkage.py --database-url-env --dry-run >/dev/null
docker run --rm --network host -u 0 \
  --env-file "`$root/app/deploy/.env" \
  -v "`$stage/app/backend:/staged:ro" \
  -v "`$stage/scripts/migrations:/migrations:ro" \
  -w /staged "`$backend_image" \
  python /migrations/013_asset_scan_authorizations.py --database-url-env --dry-run >/dev/null
printf '%s\n' '$commit' > "`$root/app/REVISION"

source_changed=0
db_changed=0
trap - ERR
rm -rf "`$stage" "`$archive"
"@
        $remoteScript | & $ssh -o BatchMode=yes -o ConnectTimeout=15 "$SshUser@$VpsHost" "bash -s"
        if ($LASTEXITCODE -ne 0) { throw "Remote release failed; source rollback was attempted." }
        Write-Host "Released $commit to $SshUser@$VpsHost." -ForegroundColor Green
    }
    finally {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    }
}
finally {
    Pop-Location
}
