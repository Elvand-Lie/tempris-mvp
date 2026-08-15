[CmdletBinding()]
param(
    [switch]$Deploy,
    [string]$VpsHost = "187.127.114.218",
    [string]$SshUser = "tempris",
    [string]$RemoteRoot = "/home/tempris",
    [string]$PostgresContainer = "tempris-app-postgres-1"
)

$ErrorActionPreference = "Stop"
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
stage="`$(mktemp -d)"
restore_stage=''
source_changed=0
db_changed=0

rollback() {
  status=`$?
  set +e
  echo "Release failed; restoring the verified database, report artifacts, source, and frontend." >&2
  if [ "`$db_changed" -eq 1 ] && [ -s "`$db_backup" ]; then
    docker stop tempris_backend >/dev/null 2>&1
    docker cp "`$db_backup" "`$pg_container:/tmp/`$release.rollback.dump"
    docker exec -e RELEASE="`$release" "`$pg_container" sh -lc 'pg_restore -U "`$POSTGRES_USER" -d "`$POSTGRES_DB" --clean --if-exists --no-owner --no-privileges /tmp/`$RELEASE.rollback.dump' || echo "ERROR: automatic database restoration failed; use `$(printf %q "`$db_backup") manually." >&2
    docker exec "`$pg_container" rm -f "/tmp/`$release.rollback.dump"
  fi
  if [ -s "`$report_backup" ]; then
    rm -rf "`$root/app/backend/data/reports"
    mkdir -p "`$root/app/backend/data"
    tar -C "`$root/app/backend/data" -xzf "`$report_backup"
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

mkdir -p "`$(dirname "`$source_backup")" "`$(dirname "`$db_backup")" "`$(dirname "`$report_backup")" "`$(dirname "`$migration_report")"
tar -C "`$root" -czf "`$source_backup" --exclude='app/deploy/.env' --exclude='app/freellmapi/.env' --exclude='app/backend/data' app
tar -tzf "`$source_backup" >/dev/null
tar -C "`$stage" -xzf "`$archive"
mkdir -p "`$root/app/backend/data/reports"
tar -C "`$root/app/backend/data" -czf "`$report_backup" reports
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
