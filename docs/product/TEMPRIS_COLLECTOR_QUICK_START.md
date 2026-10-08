# Tempris Collector — Windows Quick Start

*Applies to `tempris-collector.exe` v0.4.x.*

## 1. What the Collector is

The Tempris Collector is a small Windows agent that connects out to your Tempris V2 tenant over an authenticated WebSocket. Tempris uses it to check reachability of **private/internal assets** and to run **SCOUT** scans (and STRIKE tool runs) from inside your network — machines Tempris' cloud scanner cannot reach. It only ever connects outward; no inbound firewall rule is needed.

## 2. Before installation

- A Windows machine (server or workstation) that has **network access to the internal assets you want scanned**, kept powered on.
- An administrator login to Tempris V2 (https://sandbox.tempris.tech/v2-assets/).
- In Tempris, open **Collectors Console** and click **Register New Internal Collector** → **Generate Enrollment Code**.
- Copy the three values shown: **Enrollment Code**, **Collector ID**, and **Server Base URL** (each has a **Copy** button).

> The enrollment code is **single-use and expires after 15 minutes** (the console shows a live countdown). If it expires or a wrong attempt consumes it, generate a new one — this never affects the collector profile itself.

## 3. Install / first run

The executable is a foreground program (there is no Windows *service*); after enrollment it registers itself to start automatically at boot as a **scheduled task**. Run everything from an **elevated (Administrator) Command Prompt** in the folder containing the exe.

One command enrolls, starts the headless daemon, and registers the boot task:

```bat
tempris-collector.exe --core --server-url "https://sandbox.tempris.tech/v2-assets" --enroll "<ENROLLMENT_CODE>" --collector-id "<COLLECTOR_ID>"
```

- `--core` runs it headless (no GUI window). Omit it to get the assistant GUI instead.
- `--server-url` is optional on standard builds (it defaults to the URL above) but is shown in the console dialog — including it is the safe practice.
- The boot task is created as **`TemprisCollectorCore`** (runs `C:\ProgramData\Tempris\Collector\bin\tempris-collector.exe --core` as SYSTEM at start). The exe copies itself to that protected path on first run — that copy is the live binary.

Keep the window open (or start the task) so the collector connects immediately instead of waiting for the next boot:

```bat
schtasks /Run /TN TemprisCollectorCore
```

## 4. Verify connection

Back in **Collectors Console**, your collector's badge should change from **Unenrolled/OFFLINE** to **CONNECTED** within a minute. *Connected* means Tempris has received a recent authenticated heartbeat from the agent. A machine that shuts down or loses network simply shows **OFFLINE** until it heartbeats again.

## 5. Using it

1. In **Assets Console**, create or edit an internal asset and set **Network Scope** to `Internal / Collector route` — it will be assigned to your collector (shown on the asset, e.g. `INTERNAL (Collector: <name>)`).
2. On the asset's **⋮** menu, use **Request Scan Auth** / **Approve Scan Auth** (approving is an admin action — scans never run without explicit authorization).
3. Open **SCOUT**, select the asset, choose a fixed scan profile (Service discovery / Vulnerability assessment) and launch. Results appear in SCOUT and flow into Intake & Triage.

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| "Invalid enrollment code" / code expired | Codes are single-use with a **15-minute** life. In Collectors Console, register a new code for the collector and rerun the enrollment command. |
| Collector stays **OFFLINE** | Check the server URL (must be `https://sandbox.tempris.tech/v2-assets`), outbound HTTPS/WebSocket access, and TLS (corporate proxies must not block wss). Then restart: `schtasks /End /TN TemprisCollectorCore` followed by `schtasks /Run /TN TemprisCollectorCore`. |
| **REVOKED** collector | A collector revoked in the console can never reconnect. Register a new collector profile and re-enroll. |
| Re-enrolling / moving machines | Do **not** delete the files under `C:\ProgramData\Tempris\Collector\` casually — `protected_identity.dat` and `state.json` are the collector's cryptographic identity. Delete them only when you intentionally want to wipe the identity and enroll as a brand-new collector. |

**Files and logs** (all under `C:\ProgramData\Tempris\Collector\`): `state.json` (enrollment/state), `protected_identity.dat` (identity key), `toolchain-state.json`, `runtime.json`, and the `logs\` folder for diagnostics. Log verbosity follows the standard tracing filter (e.g. set `RUST_LOG=debug` before starting for verbose output).

**Task management:** `schtasks /Query /TN TemprisCollectorCore` (status) · `/Run` (start) · `/End` (stop). There is no Windows service — do not look for one in `services.msc`.

## Verifying the executable (integrity)

If Tempris supplied a SHA-256 value alongside the `.exe` (no checksum file ships inside the package itself), verify before running:

```bat
certutil -hashfile tempris-collector.exe SHA256
```

Compare the output hash, character for character, with the value from Tempris. If they differ, do not run the file and contact us.
