[CmdletBinding()]
param(
    [string]$SshTarget = "tempris@187.127.114.218",
    [string]$RemoteRoot = "/home/tempris",
    [string]$BaseUrl = "https://sandbox.tempris.tech",
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "workDocs\tempris-account-credentials.local.md")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$accounts = [ordered]@{
    "TEMPRIS_PASS_SUPERADMIN" = [ordered]@{ Email = "sherie@tempris.com"; Role = "Superadmin" }
    "TEMPRIS_PASS_ADMIN" = [ordered]@{ Email = "admin@tempris.com"; Role = "Admin" }
    "TEMPRIS_PASS_ANALYST" = [ordered]@{ Email = "analyst@tempris.com"; Role = "Analyst" }
    "TEMPRIS_PASS_VIEWER" = [ordered]@{ Email = "viewer@tempris.com"; Role = "Viewer" }
    "TEMPRIS_PASS_READONLY" = [ordered]@{ Email = "readonly@tempris.com"; Role = "Read-only" }
}

function New-TemprisPassword {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

$credentials = [ordered]@{}
foreach ($entry in $accounts.GetEnumerator()) {
    $credentials[$entry.Key] = New-TemprisPassword
}

if (($credentials.Values | Select-Object -Unique).Count -ne $accounts.Count) {
    throw "Password generation produced duplicate values."
}

$outputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$generatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$markdown = @(
    "# Tempris sandbox account credentials"
    ""
    "> Local secret generated $generatedAt. This file is Git-ignored. Do not commit, paste into tickets, or send through chat."
    ""
    "| Email | Role | Password |"
    "|---|---|---|"
)
foreach ($entry in $accounts.GetEnumerator()) {
    $password = $credentials[$entry.Key]
    $markdown += "| ``$($entry.Value.Email)`` | $($entry.Value.Role) | ``$password`` |"
}
$markdown += ""

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($OutputPath, $markdown, $utf8NoBom)

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("tempris-password-rotation-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$updatesPath = Join-Path $temporaryDirectory "credentials.env"
$helperPath = Join-Path $temporaryDirectory "rotate_credentials.py"
$remoteSuffix = [guid]::NewGuid().ToString("N")
$remoteUpdates = "/tmp/tempris-credentials-$remoteSuffix.env"
$remoteHelper = "/tmp/tempris-rotate-$remoteSuffix.py"

try {
    $updates = foreach ($entry in $credentials.GetEnumerator()) {
        "$($entry.Key)=$($entry.Value)"
    }
    [System.IO.File]::WriteAllLines($updatesPath, $updates, $utf8NoBom)

    $helper = @'
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

env_path = Path(sys.argv[1]).resolve()
updates_path = Path(sys.argv[2]).resolve()
backup_dir = Path(sys.argv[3]).resolve()
required = {
    "TEMPRIS_PASS_SUPERADMIN",
    "TEMPRIS_PASS_ADMIN",
    "TEMPRIS_PASS_ANALYST",
    "TEMPRIS_PASS_VIEWER",
    "TEMPRIS_PASS_READONLY",
}

updates = {}
for raw in updates_path.read_text(encoding="utf-8").splitlines():
    key, value = raw.split("=", 1)
    updates[key] = value
if set(updates) != required:
    raise SystemExit("Credential update file does not contain the five required keys")
if any(not value or value == "demo" for value in updates.values()):
    raise SystemExit("Blank or demo passwords are forbidden")
if len(set(updates.values())) != len(updates):
    raise SystemExit("Duplicate passwords are forbidden")

backup_dir.mkdir(parents=True, exist_ok=True)
timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backup_path = backup_dir / f"deploy.env.before-password-rotation.{timestamp}"
shutil.copy2(env_path, backup_path)
os.chmod(backup_path, 0o600)

seen = set()
output = []
for line in env_path.read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in line:
        key = line.split("=", 1)[0].strip()
        if key in updates:
            output.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
    output.append(line)
for key in sorted(required - seen):
    output.append(f"{key}={updates[key]}")

descriptor, temporary_name = tempfile.mkstemp(prefix=".env.rotate.", dir=str(env_path.parent))
try:
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(output) + "\n")
    os.chmod(temporary_name, 0o600)
    os.replace(temporary_name, env_path)
finally:
    if os.path.exists(temporary_name):
        os.unlink(temporary_name)
updates_path.unlink(missing_ok=True)
print(f"Credential environment updated; backup created at {backup_path}")
'@
    [System.IO.File]::WriteAllText($helperPath, $helper, $utf8NoBom)

    Invoke-External "scp" @($updatesPath, "${SshTarget}:$remoteUpdates")
    Invoke-External "scp" @($helperPath, "${SshTarget}:$remoteHelper")

    $remoteEnv = "$RemoteRoot/app/deploy/.env"
    $remoteBackup = "$RemoteRoot/backups/credentials"
    $remoteCompose = "$RemoteRoot/app/deploy/docker-compose.prod.yml"
    $remoteCommand = "chmod 600 '$remoteUpdates' '$remoteHelper' && python3 '$remoteHelper' '$remoteEnv' '$remoteUpdates' '$remoteBackup' && rm -f '$remoteHelper' && cd '$RemoteRoot/app/deploy' && docker compose -f '$remoteCompose' up -d --force-recreate backend"
    Invoke-External "ssh" @($SshTarget, $remoteCommand)

    $healthy = $false
    for ($attempt = 1; $attempt -le 20; $attempt += 1) {
        try {
            $health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/health" -TimeoutSec 10
            if ($health.status -eq "Tempris API running") {
                $healthy = $true
                break
            }
        }
        catch {
            if ($attempt -eq 20) { throw }
        }
        Start-Sleep -Seconds 3
    }
    if (-not $healthy) {
        throw "Backend health check did not recover after password rotation."
    }

    foreach ($entry in $accounts.GetEnumerator()) {
        $body = @{
            email = $entry.Value.Email
            password = $credentials[$entry.Key]
        } | ConvertTo-Json -Compress
        $session = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" -ContentType "application/json" -Body $body -TimeoutSec 20
        if (-not $session.access_token) {
            throw "Login verification failed for $($entry.Value.Email)"
        }
        $headers = @{ Authorization = "Bearer $($session.access_token)" }
        Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/logout" -Headers $headers -TimeoutSec 20 | Out-Null
        Write-Host "Verified login: $($entry.Value.Email)"
    }

    Write-Host "Password rotation complete."
    Write-Host "Local credential file: $OutputPath"
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
