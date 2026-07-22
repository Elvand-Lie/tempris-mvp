[CmdletBinding()]
param(
    [switch]$Deploy,
    [Parameter(Mandatory = $true)]
    [string]$VpsHost,
    [Parameter(Mandatory = $true)]
    [string]$SshUser,
    [string]$RemoteRoot = "/home/tempris",
    [string]$DatabaseBackupCommand
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
    if (git status --porcelain) { throw "Refusing to release: commit or stash all worktree changes first." }
    $commit = (git rev-parse HEAD).Trim()
    git diff --check
    if ($LASTEXITCODE -ne 0) { throw "git diff --check failed." }

    $preflight = "test -f '$RemoteRoot/app/deploy/docker-compose.prod.yml' -a -f '$RemoteRoot/app/deploy/.env' && command -v rsync >/dev/null && docker compose -f '$RemoteRoot/app/deploy/docker-compose.prod.yml' config -q && docker ps --format '{{.Names}}' | grep -qx tempris_backend"
    if (-not $Deploy) {
        Invoke-Remote $preflight
        Write-Host "Preflight passed for $VpsHost. Re-run with -Deploy to release commit $commit." -ForegroundColor Green
        return
    }

    Invoke-Remote $preflight
    if ([string]::IsNullOrWhiteSpace($DatabaseBackupCommand)) {
        throw "-DatabaseBackupCommand is required with -Deploy; it must create the PostgreSQL backup at `$BACKUP_FILE on the VPS."
    }
    $releaseId = "tempris-$commit-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $archive = Join-Path $env:TEMP "$releaseId.tar.gz"
    try {
        git archive --format=tar.gz --output=$archive $commit
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
backup="`$root/backups/releases/`$release.tar.gz"
db_backup="`$root/backups/database/`$release.dump"
stage="`$(mktemp -d)"
mkdir -p "`$(dirname "`$backup")"
mkdir -p "`$(dirname "`$db_backup")"
tar -C "`$root" -czf "`$backup" --exclude='app/deploy/.env' --exclude='app/freellmapi/.env' --exclude='app/backend/data' app
tar -C "`$stage" -xzf "`$archive"
cd "`$root"
export BACKUP_FILE="`$db_backup"
$DatabaseBackupCommand
test -s "`$db_backup"
docker exec tempris_backend sh -lc 'command -v pg_restore >/dev/null'
rsync -a --delete --exclude='deploy/.env' --exclude='freellmapi/.env' --exclude='backend/data/' "`$stage/app/" "`$root/app/"
install -m 0644 "`$stage/app/backend/data/v62_debrief_findings.json" "`$root/app/backend/data/v62_debrief_findings.json"
cd "`$root/app/deploy"
docker cp "`$stage/scripts/migrations/006_add_sss_sub_class.py" tempris_backend:/tmp/006_add_sss_sub_class.py
docker cp "`$db_backup" tempris_backend:/tmp/`$release.dump
docker compose -f docker-compose.prod.yml exec -T backend python /tmp/006_add_sss_sub_class.py --database-url-env --backup-file /tmp/`$release.dump
docker compose -f docker-compose.prod.yml up -d --build
curl --fail --silent --show-error --max-time 20 http://127.0.0.1:8000/api/health >/dev/null
rm -rf "`$stage" "`$archive"
"@
        Invoke-Remote ("bash -s <<'EOF'`n" + $remoteScript + "`nEOF")
        Write-Host "Released $commit to $VpsHost." -ForegroundColor Green
    }
    finally {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    }
}
finally {
    Pop-Location
}
