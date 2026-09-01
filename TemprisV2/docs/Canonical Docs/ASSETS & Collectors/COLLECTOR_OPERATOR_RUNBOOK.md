# Tempris Collector V0.2 — Operator Runbook

> **Canonical Reference**: For the full, comprehensive specification across all 30+ operational, cryptographic, schema, and lifecycle topics, see the authoritative [ASSETS_COLLECTORS_V0_2_CANONICAL_GUIDE.md](ASSETS_COLLECTORS_V0_2_CANONICAL_GUIDE.md).

This runbook provides complete operational guidance for system administrators, security engineers, and DevOps operators managing the Tempris Windows Collector agent in production environments.

---

## 1. Lifecycle & Architecture Summary

```text
                                  +-----------------------------+
                                  |   Control Plane (Server)    |
                                  +-----------------------------+
                                                 ^
                                    Outbound TLS | (WSS WebSocket)
                                                 v
+---------------------------------------------------------------------------------+
| Windows Host                                                                    |
|                                                                                 |
|  [ Windows Task Scheduler ] ---> [ tempris-collector.exe --core ]               |
|      (BootTrigger as SYSTEM)                  |                                 |
|                                               | Acquires Win32 Mutex:           |
|                                               | Global\TemprisCollectorCore...  |
|                                               |                                 |
|                                               v (Atomic Write)                  |
|  [ Desktop GUI Observer ] <------- [ %PROGRAMDATA%\Tempris\Collector\ ]        |
|  tempris-collector.exe              ├── state.json (Public metadata)            |
|  (Reads runtime.json/logs)          ├── protected_identity.dat (DPAPI Machine)  |
|                                     ├── runtime.json (Status snapshot)          |
|                                     └── logs\collector.log                      |
+---------------------------------------------------------------------------------+
```

---

## 2. Windows Task Scheduler Management

The collector automatically manages a Windows Scheduled Task named `TemprisCollectorCore` to ensure continuous background operation upon system boot under the local SYSTEM account.

### Task Attributes
- **Task Name**: `TemprisCollectorCore`
- **Principal / Account**: `NT AUTHORITY\SYSTEM` (`S-1-5-18`)
- **Trigger**: `At startup (BootTrigger)`
- **Action Command**: `"%PROGRAMDATA%\Tempris\Collector\bin\tempris-collector.exe"`
- **Action Arguments**: `"--core"`
- **Run Level**: `HighestAvailable`
- **Execution Time Limit**: `PT0S` (Infinite / No timeout kill)
- **Multiple Instances Policy**: `IgnoreNew`
- **Security Descriptor (SDDL)**: `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)`

### Checking Task Registration Status
In PowerShell:
```powershell
schtasks /Query /TN "TemprisCollectorCore" /FO LIST /V
```

### Administrative Boot Toggle (UAC)
Administrators can enable or disable automatic startup at boot without unregistering the task:
```powershell
# Disable autostart on boot:
schtasks /Change /TN "TemprisCollectorCore" /Disable

# Enable autostart on boot:
schtasks /Change /TN "TemprisCollectorCore" /Enable
```

### Setup & Repair
To repair or re-register the XML template task, run `TemprisCollectorSetup.exe` with Administrator privileges:
```powershell
.\TemprisCollectorSetup.exe
```

---

## 3. Storage Hierarchy & Permissions

All local files are stored under:
```text
C:\ProgramData\Tempris\Collector\
```

| File / Directory | Scope & Sensitivity | Access Control (DACL) | Description |
| :--- | :--- | :--- | :--- |
| `bin\tempris-collector.exe` | Stable Binary Location | SYSTEM/Admin Full, Users Read/Exec | Protected binary executable. |
| `state.json` | Non-sensitive, Public | Observer Tier: SYSTEM/Admin Full, Users Read-Only | JSON metadata containing `collector_id`, `collector_name`, `server_url`, `public_key`, and `schema_version: 2`. |
| `protected_identity.dat` | Highly Sensitive | Secret Tier: SYSTEM/Admin Full, Users NO ACCESS | 32-byte Ed25519 private signing seed encrypted via `CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE \| CRYPTPROTECT_UI_FORBIDDEN`. |
| `runtime.json` | Non-authoritative, Volatile | Observer Tier: SYSTEM/Admin Full, Users Read-Only | JSON snapshot of daemon status, heartbeat, jobs count, and current activity. |
| `logs\collector.log` | Operational Log | Observer Tier: SYSTEM/Admin Full, Users Read-Only | Rotating text log file capped at 5 MB (max 3 backups). |

### Security Invariant Checklist
- The Ed25519 private signing seed is never written to disk in unencrypted form.
- The `state.json` and `runtime.json` files contain zero private keys, secret seeds, DPAPI blobs, or tokens.
- Rotating log files contain zero secrets, preimages, or raw authentication challenge bodies.

---

## 4. Operational Monitoring & Live Tailing

### Live Log Tailing
To inspect live activity on a collector workstation:
```powershell
Get-Content -Path "$env:ProgramData\Tempris\Collector\logs\collector.log" -Tail 50 -Wait
```

### Checking Daemon Status via JSON
To inspect the latest daemon telemetry programmatically:
```powershell
Get-Content -Path "$env:ProgramData\Tempris\Collector\runtime.json" | ConvertFrom-Json
```

### Log Rotation Rules
- Maximum file size: **5 MB**
- Maximum backups retained: **3** (`collector.log.1`, `collector.log.2`, `collector.log.3`)
- Total disk footprint capped at **~20 MB**.

---

## 5. Failure Modes & Disaster Recovery

### 5.1 Storage Corruption (`StorageError`)
**Symptom**: GUI displays red **Storage Recovery Required** screen; `--core` logs `Storage corruption` and terminates.

**Root Causes**:
1. `protected_identity.dat` was copied across physical machines (breaking machine DPAPI key decryption).
2. Disk write corruption or partial file deletion of `state.json`.

**Remediation Options**:
- **Option 1 (Retry)**: If transient file locking caused the error, click **Retry Load** in the GUI.
- **Option 2 (Advanced Reset)**: In GUI, click **Reset Registration...** and confirm. In CLI, execute an Advanced Reset (see Section 6).

---

### 5.2 Policy Quarantining / Revocation (`QUARANTINED` / `REVOKED`)
**Symptom**: Log displays `WebSocket closed by server (code 1008): policy violation`; collector stops reconnecting.

**Behavior**:
- The collector halts the reconnection loop immediately to prevent network storms.
- Local credentials (`state.json` and `protected_identity.dat`) remain safely preserved on disk.

**Remediation**:
- Contact the Tempris Control Plane administrator to un-quarantine or restore the collector profile.
- Once restored, restart the collector (`tempris-collector.exe --core`).

---

### 5.3 Mutex Collision (`AlreadyRunning`)
**Symptom**: Launching `tempris-collector.exe --core` immediately logs `Another Tempris Collector core instance is already running. Exiting cleanly.` and exits with code `0`.

**Behavior**:
- This is by design: the Win32 Named Mutex (`Global\TemprisCollectorCoreSingleton`) prevents duplicate active daemon processes.
- To view live status without stopping the daemon, launch the GUI without flags (`tempris-collector.exe`).

---

## 6. Advanced Reset & Decommissioning

Performing an **Advanced Reset** decommissions the local collector agent and returns the system to a clean, unenrolled state.

### What Advanced Reset Performs:
1. Shuts down any active client loops and closes live WebSocket sessions.
2. Unregisters and deletes the `TemprisCollectorCore` Windows Scheduled Task.
3. Permanently deletes `state.json`, `protected_identity.dat`, and `runtime.json`.
4. Resets the GUI to the initial Setup & Enrollment view.

### Method A: Via Desktop GUI
1. Open `tempris-collector.exe`.
2. Navigate to the **Advanced** tab.
3. Under **Reset Collector Registration**, click **Reset Collector Registration...**.
4. Confirm the prompt by clicking **Yes, Delete Credentials & Reset**.

### Method B: Manual CLI Decommissioning
```powershell
# 1. Stop any running core processes
Stop-Process -Name "tempris-collector" -Force -ErrorAction SilentlyContinue

# 2. Delete the scheduled task
schtasks /Delete /TN "TemprisCollectorCore" /F

# 3. Wipe the storage credentials and runtime snapshots
Remove-Item -Path "$env:ProgramData\Tempris\Collector\state.json" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramData\Tempris\Collector\protected_identity.dat" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramData\Tempris\Collector\runtime.json" -Force -ErrorAction SilentlyContinue
```

---

## 7. Operational Health Checklist

| Health Check | Verification Command / Step | Expected Healthy State |
| :--- | :--- | :--- |
| **Process Status** | `Get-Process tempris-collector -ErrorAction SilentlyContinue` | Exactly 1 process running with `--core` argument. |
| **Singleton Mutex** | Check `logs\collector.log` | `Acquired core singleton mutex` logged without collisions. |
| **Auto-Start Task** | `schtasks /Query /TN "TemprisCollectorCore"` | Status: `Ready` or `Running`. |
| **Connection Status** | `runtime.json` `status` property | `"CONNECTED"`. |
| **Heartbeat Cadence** | `runtime.json` `last_heartbeat` | Updated within the last 30 seconds. |
| **Secret Audit** | Static scan of `state.json` | 0 private keys, 0 seeds, DPAPI ciphertext only in `.dat`. |
