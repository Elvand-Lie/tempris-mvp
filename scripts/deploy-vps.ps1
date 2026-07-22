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
stage="`$(mktemp -d)"
restore_stage=''
source_changed=0

rollback() {
  status=`$?
  if [ "`$source_changed" -eq 1 ] && [ -s "`$source_backup" ]; then
    restore_stage="`$(mktemp -d)"
    tar -C "`$restore_stage" -xzf "`$source_backup"
    rsync -a --delete --exclude='deploy/.env' --exclude='freellmapi/.env' --exclude='backend/data/' "`$restore_stage/app/" "`$root/app/"
    cd "`$root/app/deploy"
    docker compose -f docker-compose.prod.yml up -d --build || true
  fi
  rm -rf "`$stage" "`$restore_stage" "`$archive"
  exit "`$status"
}
trap rollback ERR

mkdir -p "`$(dirname "`$source_backup")" "`$(dirname "`$db_backup")"
tar -C "`$root" -czf "`$source_backup" --exclude='app/deploy/.env' --exclude='app/freellmapi/.env' --exclude='app/backend/data' app
tar -C "`$stage" -xzf "`$archive"

docker exec -e RELEASE="`$release" "`$pg_container" sh -lc 'pg_dump -U "`$POSTGRES_USER" -d "`$POSTGRES_DB" -Fc -f /tmp/`$RELEASE.dump && pg_restore --list /tmp/`$RELEASE.dump >/dev/null'
docker cp "`$pg_container:/tmp/`$release.dump" "`$db_backup"
docker exec "`$pg_container" rm -f "/tmp/`$release.dump"
test -s "`$db_backup"

docker cp "`$stage/scripts/migrations/006_add_sss_sub_class.py" tempris_backend:/tmp/006_add_sss_sub_class.py
docker cp "`$db_backup" "tempris_backend:/tmp/`$release.dump"
docker exec tempris_backend python /tmp/006_add_sss_sub_class.py --database-url-env --backup-file "/tmp/`$release.dump" --externally-verified-backup
docker exec tempris_backend rm -f /tmp/006_add_sss_sub_class.py "/tmp/`$release.dump"

source_changed=1
rsync -a --delete --exclude='deploy/.env' --exclude='freellmapi/.env' --exclude='backend/data/' "`$stage/app/" "`$root/app/"
docker cp "`$stage/app/backend/data/v62_debrief_findings.json" tempris_backend:/app/data/v62_debrief_findings.json

cd "`$root/app/deploy"
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml exec -T backend python -c 'from services.database import SessionLocal; from models import Finding; from scripts.seed_findings import seed_v62_debrief_findings; db = SessionLocal(); existing = {row[0] for row in db.query(Finding.id).all()}; seed_v62_debrief_findings(db, existing); db.commit(); db.close()'
curl --fail --silent --show-error --retry 10 --retry-delay 3 --max-time 20 http://127.0.0.1:8000/api/health >/dev/null

source_changed=0
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
