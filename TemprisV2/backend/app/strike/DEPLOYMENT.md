# STRIKE server vantage — deployment prerequisites

The STRIKE toolbox runs from two vantages:

- **collector** — dispatched over the collector's authenticated WSS to the
  enrolled host the user selected (unchanged).
- **server** — executed in-process by the platform itself
  (`app/strike/sandbox.py`, driven by `app/strike/server_runner.py`).

This note covers the **server** vantage only: what a deploy must provide, and
how the code behaves when it is missing.

## Principle: fail closed, never fabricate

Every server-vantage prerequisite is checked **before a process is spawned**
(`sandbox.server_prerequisite_error`, consulted by `runs.create_run` for the
`server` plane, and re-checked by the runner). A missing prerequisite is a
visible `422 run_config_invalid` at run creation — never a queued run that dies
in the background, and never a "completed" run with empty output.

The check is two-layered on purpose: creation-time (so the console gets an
immediate answer) and run-time (`shutil.which` / directory existence at spawn,
because a toolchain can disappear between the two).

## Required binaries

| Capability | Needs | Notes |
|---|---|---|
| `curl` | `curl` | Usually present already |
| `nmap` | `nmap` | `apt-get install -y nmap`. Unprivileged `-sT` connect scan only — **no `CAP_NET_RAW` / root is required or granted** |
| `nuclei` | `nuclei` **+ a pinned templates directory** | See below; the directory is mandatory |
| `ffuf` | `ffuf` | Wordlist is bundled; see below |
| `dig` | `dig`, or `nslookup` | `nslookup` is the documented substitute where `dig` is absent (e.g. Windows) |
| `httpie` | `http` / `httpie` | |
| `nc` | `nc` / `ncat` | Outbound connect only |
| `socat` | `socat` | Outbound connect only |
| `python` | `python3` / `python` | |
| `bash` | `bash` | |
| `chromium` | `chromium` / `google-chrome` / `chrome` | Server plane only |
| `mitmproxy` | `mitmdump` / `mitmproxy` | Server plane only |

Debian/Ubuntu example:

```sh
apt-get install -y curl nmap dnsutils ffuf python3 bash
```

`nuclei` and `chromium` are usually installed from their upstream releases
rather than the distro archive.

## Pinned nuclei templates (mandatory)

The server plane runs nuclei against **one pinned directory** and nothing else.
Template paths and template content are never accepted from a request, exactly
as on the collector.

```sh
# Provide the reviewed template set at deploy time, then point the app at it:
export STRIKE_NUCLEI_TEMPLATES_DIR=/opt/tempris/strike/nuclei-templates
```

- Default when unset: `/opt/tempris/strike/nuclei-templates`
  (`app/config.py`, `STRIKE_NUCLEI_TEMPLATES_DIR`).
- If the directory does not exist, the nuclei run is **refused**. This is
  deliberate: nuclei without `-t` silently falls back to its own ambient,
  auto-updated template set — the exact unpinned behaviour this vantage must
  not have. The argv also passes `-duc` (never update templates at run time) so
  the pinned set stays frozen.

## Pinned ffuf wordlist

The server ships its own reviewed public-metadata wordlist at
`app/strike/data/strike_wordlist.txt`, byte-identical to the collector's
embedded `collector/src/strike_wordlist.txt`. The two are kept as separate
files so they can be diffed and reviewed as one artifact.

- Used automatically when a run sends no inline wordlist.
- If that file is missing, the ffuf run is **refused** (never an unpinned
  fuzz).
- An inline wordlist supplied by the user is bounded
  (`runs.MAX_WORDLIST_BYTES`) and written to a server-generated path inside the
  run's private workdir — the user never supplies a path.

## nmap profiles

`nmap_profile` accepts the four existing preset names
(`ping_sweep`, `top_ports`, `service_version`, `full`). Each selects a
bounded **(ports, host-timeout)** envelope on top of one fixed flag shape
(`sandbox.NMAP_SERVER_SHAPE`): `-sT -Pn --open -T3` with rate/parallelism caps.
No profile can widen the range past 1-10000, add a privilege, or add
version/OS/script probing — the names label an envelope, **not** scan modes
(in particular `service_version` does not enable `-sV`).

## Sandbox bounds (all capabilities)

Every server-vantage run gets: a private per-run temp dir (process CWD, removed
afterwards), no shell, no interactive TTY, a scrubbed environment (no
`DATABASE_URL`/`JWT_SECRET`/cloud credentials), a hard timeout with
process-group kill, and a bounded per-stream output cap.
