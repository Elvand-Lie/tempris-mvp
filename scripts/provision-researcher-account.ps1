[CmdletBinding()]
param(
    [string]$SshTarget = "tempris@187.127.114.218",
    [string]$RemoteRoot = "/home/tempris",
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "workDocs\tempris-account-credentials.local.md")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function New-TemprisPassword {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}

$password = New-TemprisPassword
$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("tempris-researcher-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$secretPath = Join-Path $temporaryDirectory "researcher.env"
$helperPath = Join-Path $temporaryDirectory "provision_researcher.py"
$remoteSuffix = [guid]::NewGuid().ToString("N")
$remoteSecret = "/tmp/tempris-researcher-$remoteSuffix.env"
$remoteHelper = "/tmp/tempris-researcher-$remoteSuffix.py"
$utf8NoBom = [Text.UTF8Encoding]::new($false)

try {
    [IO.File]::WriteAllText($secretPath, "TEMPRIS_PASS_RESEARCHER=$password`n", $utf8NoBom)
    $helper = @"
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

env_path = Path(sys.argv[1]).resolve()
update_path = Path(sys.argv[2]).resolve()
backup_dir = Path(sys.argv[3]).resolve()
key = "TEMPRIS_PASS_RESEARCHER"
raw = update_path.read_text(encoding="utf-8").strip()
if not raw.startswith(key + "="):
    raise SystemExit("Researcher credential update is malformed")
password = raw.split("=", 1)[1]
if not password or password == "demo":
    raise SystemExit("Blank or demo researcher password is forbidden")

lines = env_path.read_text(encoding="utf-8").splitlines()
existing_passwords = {}
for line in lines:
    if line.startswith("TEMPRIS_PASS_") and "=" in line:
        env_key, value = line.split("=", 1)
        existing_passwords[env_key] = value
if password in {value for env_key, value in existing_passwords.items() if env_key != key}:
    raise SystemExit("Researcher password duplicates another account")

backup_dir.mkdir(parents=True, exist_ok=True)
timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backup_path = backup_dir / f"deploy.env.before-researcher-provision.{timestamp}"
shutil.copy2(env_path, backup_path)
os.chmod(backup_path, 0o600)

output = []
replaced = False
for line in lines:
    if line.startswith(key + "="):
        output.append(f"{key}={password}")
        replaced = True
    else:
        output.append(line)
if not replaced:
    output.append(f"{key}={password}")

descriptor, temporary_name = tempfile.mkstemp(prefix=".env.researcher.", dir=str(env_path.parent))
try:
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(output) + "\n")
    os.chmod(temporary_name, 0o600)
    os.replace(temporary_name, env_path)
finally:
    if os.path.exists(temporary_name):
        os.unlink(temporary_name)
update_path.unlink(missing_ok=True)
print(f"Researcher credential prepared; backup created at {backup_path}")
"@
    [IO.File]::WriteAllText($helperPath, $helper, $utf8NoBom)
    Invoke-External "scp" @($secretPath, "${SshTarget}:$remoteSecret")
    Invoke-External "scp" @($helperPath, "${SshTarget}:$remoteHelper")

    $remoteEnv = "$RemoteRoot/app/deploy/.env"
    $remoteBackup = "$RemoteRoot/backups/credentials"
    $remoteCommand = "chmod 600 '$remoteSecret' '$remoteHelper' && python3 '$remoteHelper' '$remoteEnv' '$remoteSecret' '$remoteBackup' && rm -f '$remoteHelper'"
    Invoke-External "ssh" @($SshTarget, $remoteCommand)

    $outputDirectory = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    $row = "| `researcher@tempris.com` | Researcher | `$password` |"
    if (Test-Path -LiteralPath $OutputPath) {
        $lines = [Collections.Generic.List[string]](Get-Content -LiteralPath $OutputPath)
        $match = -1
        for ($index = 0; $index -lt $lines.Count; $index += 1) {
            if ($lines[$index].StartsWith("| `researcher@tempris.com` |")) {
                $match = $index
                break
            }
        }
        if ($match -ge 0) { $lines[$match] = $row }
        else {
            while ($lines.Count -gt 0 -and [string]::IsNullOrWhiteSpace($lines[$lines.Count - 1])) {
                $lines.RemoveAt($lines.Count - 1)
            }
            $lines.Add($row)
            $lines.Add("")
        }
        [IO.File]::WriteAllLines($OutputPath, $lines, $utf8NoBom)
    }
    else {
        $generatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $lines = @(
            "# Tempris sandbox account credentials",
            "",
            "> Local secret generated $generatedAt. This file is Git-ignored. Do not commit, paste into tickets, or send through chat.",
            "",
            "| Email | Role | Password |",
            "|---|---|---|",
            $row,
            ""
        )
        [IO.File]::WriteAllLines($OutputPath, $lines, $utf8NoBom)
    }

    Write-Host "Researcher credential is prepared on the VPS. Deploy the matching code to activate it."
    Write-Host "Local credential file: $OutputPath"
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}