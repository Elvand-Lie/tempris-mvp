# Tempris Collector V0.2 for Windows

> **Canonical Reference**: For the full, comprehensive specification across all 30+ operational, cryptographic, schema, and lifecycle topics, see the authoritative [ASSETS_COLLECTORS_V0_2_CANONICAL_GUIDE.md](ASSETS_COLLECTORS_V0_2_CANONICAL_GUIDE.md).

Tempris Collector is a lightweight, zero-ingress internal asset reachability verification agent for Windows environments. It enables centralized asset exposure visibility without requiring inbound firewall openings, listening ports, or agent-to-agent lateral movement capabilities.

---

## 1. Architectural Highlights

- **Single Binary Duality**: One compiled executable (`tempris-collector.exe`) serves as both an interactive native desktop application (powered by `eframe`/`egui`) and a headless background core engine (`--core`).
- **Windows-Native Singleton Core Guard**: OS-level Named Mutex (`Global\TemprisCollectorCoreSingleton` with non-elevated `Local\` fallback) guarantees strictly one background verification engine connects per machine, eliminating connection thrashing.
- **Windows Task Scheduler SYSTEM Boot Auto-Start**: Registered via XML template under `NT AUTHORITY\SYSTEM` (`S-1-5-18`) with `BootTrigger` and SDDL `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)`, launching the core engine in the background at machine boot.
- **Hardware/Machine DPAPI Key Protection**: Ed25519 signing seeds are protected using machine-scoped Windows Data Protection API (`CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN`) stored in `protected_identity.dat`.
- **Bounded Operational Logging & Rotation**: Log files rotate at 5 MB (maximum 3 archived backups) at `%PROGRAMDATA%\Tempris\Collector\logs\collector.log` with a 500-line in-memory ring buffer for live GUI tailing.
- **Zero Ingress & Zero Secret Leakage**: Fully outbound WebSocket connection (`wss://`) over TLS; zero private keys, secret seeds, DPAPI blobs, or enrollment tokens appear in public JSON files, UI displays, or disk logs.

---

## 2. Storage Hierarchy

The collector stores all configuration and runtime telemetry under the machine-wide `%PROGRAMDATA%` directory:

```text
%PROGRAMDATA%\Tempris\Collector\
├── bin\
│   └── tempris-collector.exe  # Stable binary install location
├── state.json                 # Non-sensitive public collector configuration (schema_version: 2)
├── protected_identity.dat     # DPAPI machine-protected Ed25519 private signing seed (binary)
├── runtime.json               # Non-authoritative live status snapshot for decoupled GUI viewing
└── logs\
    ├── collector.log          # Active operational log (max 5 MB)
    ├── collector.log.1        # Rotated backup 1
    ├── collector.log.2        # Rotated backup 2
    └── collector.log.3        # Rotated backup 3
```

---

## 3. Quick Start & Execution Modes

### Mode A: Interactive Desktop GUI

Launch `tempris-collector.exe` without arguments to open the desktop GUI:

```powershell
.\tempris-collector.exe
```

- **Unenrolled State**: Displays the **Setup & Enrollment** view prompting for Control Plane URL, Collector Profile ID, and One-Time Enrollment Code.
- **Enrolled State**: Loads DPAPI-protected credentials, automatically connects, and presents the **Overview**, **Activity Log**, and **Advanced Settings** tabs.
- **Decoupled Observer**: If a background `--core` daemon is already active, the GUI attaches seamlessly as a decoupled live monitor reading `runtime.json` and logs. Closing the GUI leaves the background daemon running.

### Mode B: Headless Background Core Daemon

Launch with `--core` (or `--daemon` / `--headless`) to run as a background service:

```powershell
.\tempris-collector.exe --core
```

- Acquires the named singleton mutex lock.
- If another core process is already running, logs an informational notice and exits cleanly with exit code `0`.
- Periodically updates `runtime.json` atomically via `.tmp` swap + flush.
- Responds to `SIGINT` / `Ctrl+C` for graceful shutdown.

### Mode C: Setup & Installation Wizard

Run `TemprisCollectorSetup.exe` with Administrator privileges to install, repair, or configure Task Scheduler autostart:

```powershell
.\TemprisCollectorSetup.exe
```

---

## 4. Verification Engine & Safety Invariants

- **Safe Scope**: Sole supported job type is `VERIFY_TARGET` (zero application payload bytes, sequential zero-byte TCP probes to port 443 then port 80).
- **Safety Gate**: Rejects forbidden IP classes (loopback `127.0.0.0/8`, link-local `169.254.0.0/16`, multicast `224.0.0.0/4`, unspecified `0.0.0.0`, broadcast `255.255.255.255`, IPv6 equivalents) with **zero socket connections**.
- **DNS Pinning**: Single DNS resolution pinned per probe to eliminate DNS rebinding risks.
- **Discrete Backoff Ladder**: `[1s, 2s, 5s, 10s, 30s]` capped at `30s`. Resets to `1s` **strictly** upon server-issued `AUTH_SUCCESS`.
- **Policy Enforcement**:
  - `PAUSED`: Retains connection and heartbeats; executes 0 verification jobs.
  - `QUARANTINED` / `REVOKED`: Server close code `1008` immediately halts reconnect loops while preserving state on disk.

---

## 5. Building and Testing

### Prerequisites
- Rust 1.80+ (2021 edition)
- Windows 10/11 or Windows Server 2019/2022

### Build Release Binary
```powershell
cargo build --release --manifest-path collector/Cargo.toml
```
The optimized executable is output to `collector/target/release/tempris-collector.exe`.

### Run Test Suites
```powershell
# Run all unit and integration tests
cargo test --manifest-path collector/Cargo.toml
```

---

## 6. License & Support

Tempris Collector is part of the Tempris Enterprise Platform. For detailed operations and disaster recovery procedures, refer to `OPERATOR_RUNBOOK.md`.
