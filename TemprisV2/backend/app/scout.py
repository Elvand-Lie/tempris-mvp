import asyncio
import json
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from psycopg.types.json import Jsonb

from app import config
from app.db import get_db_connection
from app.exposure.models import ExposureConfirm
from app.exposure.scoring_inputs import ReachabilityEvidenceIn, record_reachability_evidence
from app.exposure.service import allocate_finding_for_cve, confirm_exposure

OUTPUT_LIMIT = 4 * 1024 * 1024
PROBE_TIMEOUT = 10
NMAP_TIMEOUT = 180
NUCLEI_TIMEOUT = 1200
_PARTIAL_OUTPUT_CHARS = 4000
_STORED_TIMEOUT_CHARS = 8192


def collector_timeout_message(engine: str, raw_result: dict) -> str:
    """Operator-facing reason for a collector scan that did not finish.

    A legacy daemon frame says only ``timeout`` and carries no profile. A
    transport timeout is the server giving up before any result frame arrives.
    A collector deadline names the envelope, elapsed time, and sanitized argv.
    """
    message = raw_result.get("error_message") or ""
    if not isinstance(message, str) or not message.strip():
        return f"Collector scan timed out for {engine}"
    if message == "timeout":
        stdout_bytes = int(raw_result.get("stdout_bytes") or 0)
        stderr_bytes = int(raw_result.get("stderr_bytes") or 0)
        return (
            "collector_deadline: termination=collector_deadline "
            f"engine={engine} exit=unset "
            f"stdout_bytes={stdout_bytes} stderr_bytes={stderr_bytes} "
            "partial_output=absent legacy_collector=true"
        )
    return message


def collector_timeout_detail(engine: str, raw_result: dict) -> str:
    """Summary plus whatever stdout/stderr the daemon managed to keep."""
    parts = [collector_timeout_message(engine, raw_result)]
    stderr = raw_result.get("stderr") or ""
    stdout = raw_result.get("stdout") or ""
    if isinstance(stderr, str) and stderr.strip():
        parts.append("partial_stderr:\n" + stderr[:_PARTIAL_OUTPUT_CHARS])
    if isinstance(stdout, str) and stdout.strip():
        parts.append("partial_stdout:\n" + stdout[:_PARTIAL_OUTPUT_CHARS])
    return "\n".join(parts)[:_STORED_TIMEOUT_CHARS]


def _is_collector_timeout(raw_result: dict) -> bool:
    message = raw_result.get("error_message") or ""
    return (
        raw_result.get("error_code") == "collector_timeout"
        or raw_result.get("status") == "timed_out"
        or message == "timeout"
        or (isinstance(message, str) and message.startswith("collector_deadline:"))
    )

PROFILE_ENGINES = {
    "SERVICE_DISCOVERY": ("nmap",),
    "VULNERABILITY_ASSESSMENT": ("nmap", "nuclei"),
}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
FINDING_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass(frozen=True)
class ProcessResult:
    state: str
    returncode: Optional[int]
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class ToolProbe:
    engine: str
    state: str
    executable: Optional[str]
    engine_version: Optional[str] = None
    templates_version: Optional[str] = None
    returncode: Optional[int] = None
    stderr: str = ""

    @property
    def available(self) -> bool:
        return self.state == "available"


class AuthorizationInvalid(RuntimeError):
    pass


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def run_bounded(
    argv: list[str],
    timeout: int,
    *,
    on_started: Optional[Callable[[], None]] = None,
) -> ProcessResult:
    """Run fixed argv with a live combined-output limit and no shell."""
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return ProcessResult("failed", None, b"", str(exc).encode("utf-8", errors="replace")[:OUTPUT_LIMIT])
    if on_started:
        try:
            on_started()
        except Exception:
            _stop_process(process)
            raise

    chunks: queue.Queue[tuple[str, Optional[bytes]]] = queue.Queue(maxsize=8)

    def drain(name: str, stream) -> None:
        try:
            while True:
                data = stream.read(65536)
                if not data:
                    break
                chunks.put((name, data))
        finally:
            chunks.put((name, None))

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()

    captured = {"stdout": bytearray(), "stderr": bytearray()}
    finished = set()
    deadline = time.monotonic() + timeout
    state = "succeeded"

    while len(finished) < 2:
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0 and state == "succeeded":
            state = "timed_out"
            _stop_process(process)
        try:
            name, data = chunks.get(timeout=max(0.01, min(0.05, remaining_time)))
        except queue.Empty:
            continue
        if data is None:
            finished.add(name)
            continue
        remaining_bytes = OUTPUT_LIMIT - sum(len(value) for value in captured.values())
        if remaining_bytes > 0:
            captured[name].extend(data[:remaining_bytes])
        if len(data) > remaining_bytes and state == "succeeded":
            state = "output_limited"
            _stop_process(process)

    for thread in threads:
        thread.join(timeout=1)
    returncode = process.wait(timeout=1)
    if state == "succeeded" and returncode != 0:
        state = "failed"
    return ProcessResult(state, returncode, bytes(captured["stdout"]), bytes(captured["stderr"]))


def _text(result: ProcessResult) -> str:
    return (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")


def _version_text(result: ProcessResult, label: Optional[str] = None) -> Optional[str]:
    if result.state != "succeeded":
        return None
    clean = re.sub(r"\x1b\[[0-9;]*m", "", _text(result))
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    if label:
        for line in lines:
            if label.lower() in line.lower():
                value = line.split(":", 1)[-1].split(" (", 1)[0].strip()
                return value or None
        return None
    return lines[0] if lines else None


def probe_tool(
    engine: str,
    runner: Callable[[list[str], int], ProcessResult] = run_bounded,
) -> ToolProbe:
    if engine not in ("nmap", "nuclei"):
        raise ValueError(f"Unsupported SCOUT engine: {engine}")
    executable = shutil.which(engine)
    if not executable:
        return ToolProbe(engine=engine, state="unavailable", executable=None)

    version_argv = [executable, "--version"] if engine == "nmap" else [executable, "-version"]
    version_result = runner(version_argv, PROBE_TIMEOUT)
    if version_result.state != "succeeded":
        return ToolProbe(
            engine=engine,
            state=version_result.state,
            executable=executable,
            returncode=version_result.returncode,
            stderr=version_result.stderr.decode("utf-8", errors="replace"),
        )

    templates_version = None
    if engine == "nuclei":
        templates_result = runner([executable, "-templates-version"], PROBE_TIMEOUT)
        if templates_result.state != "succeeded":
            return ToolProbe(
                engine=engine,
                state=templates_result.state,
                executable=executable,
                engine_version=_version_text(version_result, "Nuclei Engine Version"),
                returncode=templates_result.returncode,
                stderr=templates_result.stderr.decode("utf-8", errors="replace"),
            )
        templates_version = _version_text(templates_result, "nuclei-templates version")

    return ToolProbe(
        engine=engine,
        state="available",
        executable=executable,
        engine_version=_version_text(version_result, "Nuclei Engine Version") if engine == "nuclei" else _version_text(version_result),
        templates_version=templates_version,
    )


def nmap_argv(executable: str, target: str) -> list[str]:
    return [
        executable,
        "-Pn", "-sV", "--version-light", "--max-retries", "2",
        "--host-timeout", "120s", "--max-rate", "100",
        "--max-parallelism", "10", "-T3", "-oX", "-", "--", target,
    ]


class ScoutTemplatesUnavailable(Exception):
    """Server-plane Nuclei has no usable pinned templates directory."""


def resolve_scout_nuclei_templates_dir() -> str:
    """The pinned templates dir for server-plane SCOUT Nuclei, or a refusal.

    Fails closed: an unset/empty/missing directory is refused before the
    process spawns, because Nuclei without -t falls back to its ambient
    (and possibly auto-updated) template set — the unpinned behavior this
    plane must not have. Mirrors the STRIKE server-plane check
    (app/strike/sandbox.py::resolve_nuclei_templates_dir).
    """
    configured = (config.SCOUT_NUCLEI_TEMPLATES_DIR or "").strip()
    if not configured or not Path(configured).is_dir():
        raise ScoutTemplatesUnavailable(
            "SCOUT server-plane Nuclei templates are not deployed: "
            f"'{configured or '<unset>'}' (SCOUT_NUCLEI_TEMPLATES_DIR) is not "
            "a directory. Refusing to run against ambient templates."
        )
    has_templates = any(
        p.suffix.lower() in (".yaml", ".yml")
        for p in Path(configured).rglob("*")
        if p.is_file()
    )
    if not has_templates:
        raise ScoutTemplatesUnavailable(
            f"SCOUT_NUCLEI_TEMPLATES_DIR '{configured}' contains no .yaml/.yml "
            "templates. Refusing to run a template-less Nuclei scan."
        )
    return configured


def nuclei_argv(executable: str, target: str, templates_dir: str) -> list[str]:
    return [
        executable,
        "-t",
        templates_dir,
        "-target", target, "-jsonl", "-silent", "-no-color",
        "-disable-update-check", "-no-interactsh", "-disable-redirects",
        "-disable-unsigned-templates", "-exclude-type", "headless,code,file,javascript",
        "-severity", "low,medium,high,critical",
        "-rate-limit", "20", "-bulk-size", "1", "-concurrency", "5",
        "-timeout", "10", "-retries", "1", "-max-host-error", "10",
        "-response-size-read", "1048576", "-response-size-save", "1048576",
        "-no-stdin",
    ]


def parse_nmap_xml(payload: bytes) -> list[tuple[str, dict]]:
    root = ET.fromstring(payload)
    observations = []
    for host in root.findall("host"):
        host_evidence = {
            "addresses": [dict(node.attrib) for node in host.findall("address")],
            "hostnames": [dict(node.attrib) for node in host.findall("hostnames/hostname")],
        }
        for port in host.findall("ports/port"):
            state = port.find("state")
            service = port.find("service")
            observations.append((
                "service",
                {
                    "scanner": "nmap",
                    "host": host_evidence,
                    "port": {
                        "protocol": port.attrib.get("protocol"),
                        "portid": port.attrib.get("portid"),
                        "state": dict(state.attrib) if state is not None else None,
                        "service": dict(service.attrib) if service is not None else None,
                    },
                },
            ))
    return observations


def parse_nuclei_jsonl(payload: bytes) -> list[tuple[str, dict]]:
    return parse_nuclei_jsonl_with_stats(payload)[0]


_INVALID_UNICODE_ESCAPE = re.compile(r"\\u(?![0-9a-fA-F]{4})")
_RAW_CONTROL_CHAR = re.compile(r"[\x00-\x1f\x7f]")


def _repair_nuclei_line(raw_line: str) -> Optional[dict]:
    """One-shot repair for real-world Nuclei JSONL lines whose string values
    carry JSON-breaking content (invalid \\uXXXX escapes, raw control bytes
    from scraped responses). Recovery keeps the event parseable; it never
    invents fields. Returns None when the line is genuinely unparseable."""
    candidate = raw_line.lstrip("﻿")
    candidate = _INVALID_UNICODE_ESCAPE.sub(r"\\\\u", candidate)
    candidate = _RAW_CONTROL_CHAR.sub(lambda m: "\\u%04x" % ord(m.group(0)), candidate)
    try:
        event = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None
    return event if isinstance(event, dict) else None


def parse_nuclei_jsonl_with_stats(payload: bytes) -> tuple[list[tuple[str, dict]], dict]:
    """Identical parsing to parse_nuclei_jsonl plus line telemetry: counts over
    nonblank lines only (skipped = unrepairable malformed JSON or non-dict;
    repaired = lines recovered by one-shot repair before observation)."""
    observations = []
    total_lines = 0
    parsed_lines = 0
    repaired_lines = 0
    skipped_lines = 0
    for raw_line in payload.decode("utf-8", errors="replace").splitlines():
        if not raw_line.strip():
            continue
        total_lines += 1
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            # Real Nuclei lines embedding scraped response bytes (invalid
            # \uXXXX escapes, raw control chars) must be recovered rather than
            # silently discarded — 0 parsed must never masquerade as a clean
            # scan.
            repaired = _repair_nuclei_line(raw_line)
            if repaired is None:
                skipped_lines += 1
                continue
            event = repaired
            repaired_lines += 1
        if not isinstance(event, dict):
            skipped_lines += 1
            continue
        parsed_lines += 1
        safe_event = {
            key: event[key]
            for key in ("template-id", "matcher-name", "type", "host", "matched-at", "timestamp", "info")
            if key in event
        }
        observations.append(("template_match", {"scanner": "nuclei", "event": safe_event}))
    stats = {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "repaired_lines": repaired_lines,
        "skipped_lines": skipped_lines,
    }
    return observations, stats


_EXCERPT_LINE_CAP = 2048
_EXCERPT_TOTAL_CAP = 262144
_EXCERPT_TOTAL_MARKER = "\n…[excerpt truncated at 256 KiB]"
_SECRET_PATTERN = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|token|secret|password|private-key)(\s*[\"':=]\s*)((?:bearer\s+)?\S+(?:;[^\r\n]*)?)"
)
_WINDOWS_PATH_PATTERN = re.compile(
    r"(?i)[a-z]:\\(?:[^\\\r\n]+\\)*[^\\\r\n]*|\\\\[^\\\r\n]+\\[^\\\r\n]*|\\Users\\[^\r\n\s\"']*"
)
_UNIX_PATH_PATTERN = re.compile(
    r"(?<![\w-])/(?:home|tmp|var|usr|etc|opt)(?:/[^\r\n\s\"']*)+"
)


def _sanitize_nuclei_stdout(text: str) -> str:
    """Redact secrets and filesystem paths and cap each line, so the raw
    Nuclei stdout (including -irr embedded request/response bulk) can be
    persisted as a bounded diagnostic excerpt."""
    sanitized_lines = []
    for raw_line in text.splitlines():
        line = raw_line[:_EXCERPT_LINE_CAP]
        if len(raw_line) > _EXCERPT_LINE_CAP:
            line += "…[line truncated]"
        line = _SECRET_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", line)
        line = _WINDOWS_PATH_PATTERN.sub("[REDACTED_PATH]", line)
        line = _UNIX_PATH_PATTERN.sub("[REDACTED_PATH]", line)
        sanitized_lines.append(line)
    excerpt = "\n".join(sanitized_lines)
    if len(excerpt) > _EXCERPT_TOTAL_CAP:
        excerpt = excerpt[:_EXCERPT_TOTAL_CAP] + _EXCERPT_TOTAL_MARKER
    return excerpt


def _qualifying_nuclei(kind: str, evidence: dict) -> Optional[dict]:
    event = evidence.get("event")
    if kind != "template_match" or evidence.get("scanner") != "nuclei" or not isinstance(event, dict):
        return None
    info = event.get("info")
    classification = info.get("classification") if isinstance(info, dict) else None
    template_id = event.get("template-id")
    matcher = event.get("matcher-name")
    matched_at = event.get("matched-at")
    name = info.get("name") if isinstance(info, dict) else None
    severity = info.get("severity") if isinstance(info, dict) else None
    cve_ids = classification.get("cve-id") if isinstance(classification, dict) else None
    if not (
        isinstance(template_id, str)
        and CVE_PATTERN.fullmatch(template_id)
        and isinstance(matcher, str) and matcher.strip()
        and isinstance(matched_at, str) and matched_at.strip()
        and isinstance(name, str) and name.strip()
        and severity in FINDING_SEVERITIES
        and cve_ids == [template_id]
    ):
        return None
    return {
        "cve_id": template_id,
        "matcher": matcher,
        "matched_at": matched_at,
        "name": name,
        "severity": severity,
        "event": event,
    }


def _match_occurrence_time(match: dict, observation_created_at: Optional[datetime] = None):
    """The Nuclei match's stable occurrence time, used as the reachability
    evidence's observed_at so a retry of the same observation replays EXACTLY
    (no newly generated server time is used for a replayable observation).
    Preference order: (1) a parseable Nuclei event 'timestamp' field when the
    engine emits one, (2) the persisted scout_observations.created_at — the
    observation's own committed write time, stable across job retries.
    'matched-at' is deliberately NOT parsed as a time: Nuclei emits the
    matched URL there, not an occurrence time."""
    event = match.get("event") or {}
    candidate = event.get("timestamp")
    if isinstance(candidate, str) and candidate.strip():
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed, "nuclei_timestamp"
    if observation_created_at is not None:
        if observation_created_at.tzinfo is None:
            observation_created_at = observation_created_at.replace(tzinfo=timezone.utc)
        return observation_created_at, "observation_created_at"
    return None, None


def _scout_reachability_byproduct(
    conn,
    job: dict,
    observation_id: uuid.UUID,
    exposure_id: uuid.UUID,
    match: dict,
    observation_created_at: Optional[datetime] = None,
) -> None:
    """SCOUT reachability byproduct (PRD §3.3.2): a qualifying Nuclei match is
    a demonstrated network hit, so confirmation records exact-exposure
    reachability IN THE SAME TRANSACTION, bound to the exact exposure episode
    returned by confirm_exposure. Vantage derives from the job route
    (CENTRAL_PUBLIC → external, COLLECTOR_INTERNAL → internal). The stable
    source identity is the SCOUT observation itself
    (source_object_type='scout_observation', source_object_id=observation_id).
    The occurrence time is the match's stable time — the Nuclei event
    'timestamp' when present, else the persisted observation created_at — so a
    retry of the same observation replays EXACTLY instead of using a newly
    generated server time; the provenance records which source supplied it.
    Full match provenance is preserved: job id, observation id, scanner, job
    route, derived vantage, CVE/template id, matcher name, matched-at, and the
    matched event reference. Runs inside the caller's transaction —
    confirmation and reachability commit or roll back together."""
    route = job.get("route") or (
        "CENTRAL_PUBLIC" if job.get("network_scope") == "internet" else "COLLECTOR_INTERNAL"
    )
    vantage = {"CENTRAL_PUBLIC": "external", "COLLECTOR_INTERNAL": "internal"}[route]
    occurrence_time, occurrence_source = _match_occurrence_time(match, observation_created_at)
    record_reachability_evidence(
        conn,
        uuid.UUID(str(job["tenant_id"])),
        exposure_id,
        ReachabilityEvidenceIn(
            vantage=vantage,
            evidence={
                "source": "scout",
                "scanner": "nuclei",
                "scout_job_id": str(job["id"]),
                "scout_observation_id": str(observation_id),
                "job_route": route,
                "vantage": vantage,
                "cve_id": match["cve_id"],
                "template_id": match["cve_id"],
                "matcher_name": match["matcher"],
                "matched_at": match["matched_at"],
                "event": match["event"],
                "occurrence_time_source": occurrence_source,
            },
            observed_at=occurrence_time,
        ),
        actor_id=f"scout:{job['id']}",
        actor_role="system",
        producer="scout",
        source_object_type="scout_observation",
        source_object_id=str(observation_id),
    )


def _normalize_nuclei_observation(conn, job: dict, observation_id: uuid.UUID) -> None:
    tenant_id = uuid.UUID(str(job["tenant_id"]))
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT o.kind, o.evidence, o.created_at, t.engine, a.id AS asset_id, a.status
            FROM scout_observations o
            JOIN scout_tool_runs t
              ON t.tenant_id = o.tenant_id AND t.job_id = o.job_id AND t.id = o.tool_run_id
            JOIN scout_jobs j
              ON j.tenant_id = o.tenant_id AND j.id = o.job_id
            JOIN assets a
              ON a.tenant_id = j.tenant_id AND a.id = j.asset_id
            WHERE o.tenant_id = %s AND o.job_id = %s AND o.id = %s
              AND t.engine = 'nuclei' AND o.kind = 'template_match'
            """,
            (str(tenant_id), str(job["id"]), str(observation_id)),
        )
        parent = cur.fetchone()
        if (
            not parent
            or parent["engine"] != "nuclei"
            or parent["status"] != "active"
            or str(parent["asset_id"]) != str(job["asset_id"])
        ):
            raise RuntimeError("Nuclei observation parentage is invalid")
        match = _qualifying_nuclei(parent["kind"], parent["evidence"])
        if not match:
            return
        # The observation's persisted write time — the stable fallback
        # occurrence time when the Nuclei event carries no 'timestamp'.
        observation_created_at = parent["created_at"]

        cur.execute(
            "SELECT state FROM canonical_vulnerabilities WHERE cve_id = %s",
            (match["cve_id"],),
        )
        canonical = cur.fetchone()
        if not canonical or canonical["state"] != "PUBLISHED":
            return

    # Finding reuse + convergence are owned entirely by the shared, serialized
    # CVE allocator and the shared confirmation command inside this one
    # transaction: the allocator reuses the tenant's finding for the CVE
    # regardless of its status (recurrence never duplicates a concept), and the
    # command idempotently replays an existing current episode or confirms a
    # new one. No separate SCOUT dedupe/locking path exists.
    finding_id = allocate_finding_for_cve(
        conn,
        tenant_id,
        match["cve_id"],
        default_title=match["name"],
        default_severity=match["severity"],
        default_description=f"SCOUT Nuclei exact match ({match['matcher']})",
        actor_id=f"scout:{job['id']}",
        actor_role="system",
    )

    confirmation = confirm_exposure(
        conn,
        tenant_id,
        ExposureConfirm(
            finding_id=finding_id,
            asset_id=uuid.UUID(str(job["asset_id"])),
            evidence={
                "source": "scout",
                "scanner": "nuclei",
                "scout_job_id": str(job["id"]),
                "scout_observation_id": str(observation_id),
                "requested_by": job["requested_by"],
                "template_id": match["cve_id"],
                "matcher_name": match["matcher"],
                "matched_at": match["matched_at"],
                "event": match["event"],
            },
        ),
        actor_id=f"scout:{job['id']}",
        actor_role="system",
    )

    # Reachability is a byproduct of confirmation (§3.3.2): attach it to the
    # EXACT episode the confirmation returned (created or replayed), in this
    # same transaction, carrying the full normalized match provenance and the
    # stable occurrence time (event timestamp or the observation's persisted
    # created_at). A replayed confirmation still binds reachability to the
    # committed episode; the observation-keyed source identity keeps the write
    # idempotent across job retries.
    _scout_reachability_byproduct(
        conn,
        job,
        observation_id,
        confirmation.exposure.id,
        match,
        observation_created_at=observation_created_at,
    )


def _job_row(job_id: uuid.UUID, tenant_id: uuid.UUID) -> dict:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM scout_jobs WHERE id = %s AND tenant_id = %s",
                (str(job_id), str(tenant_id)),
            )
            row = cur.fetchone()
    if not row:
        raise AuthorizationInvalid("SCOUT job is unavailable")
    return dict(row)


def _validate_locked(cur, job: dict) -> None:
    now = datetime.now(timezone.utc)
    route = job.get("route") or ("CENTRAL_PUBLIC" if job.get("network_scope") == "internet" else "COLLECTOR_INTERNAL")

    if route == "CENTRAL_PUBLIC":
        cur.execute(
            """
            SELECT
                a.status AS asset_status, a.target_type AS asset_target_type,
                a.normalized_target AS asset_target, a.network_scope AS asset_scope,
                au.status AS authorization_status, au.target_type AS authorization_target_type,
                au.normalized_target AS authorization_target, au.network_scope AS authorization_scope,
                au.approved_at, au.expires_at
            FROM assets a
            JOIN asset_scan_authorizations au
              ON au.tenant_id = a.tenant_id AND au.asset_id = a.id
            WHERE a.tenant_id = %s AND a.id = %s AND au.id = %s
            FOR UPDATE OF a, au
            """,
            (str(job["tenant_id"]), str(job["asset_id"]), str(job["authorization_id"])),
        )
        current = cur.fetchone()
        valid = current and (
            current["asset_status"] == "active"
            and current["asset_scope"] == "internet"
            and current["authorization_status"] == "approved"
            and current["expires_at"] is not None
            and current["expires_at"] > now
            and current["asset_target_type"] == job["target_type"]
            and current["asset_target"] == job["normalized_target"]
            and current["asset_scope"] == job["network_scope"]
            and current["authorization_target_type"] == job["target_type"]
            and current["authorization_target"] == job["normalized_target"]
            and current["authorization_scope"] == job["network_scope"]
            and current["approved_at"] == job["authorization_approved_at"]
            and current["expires_at"] == job["authorization_expires_at"]
        )
        if not valid:
            raise AuthorizationInvalid("Current exact-target authorization is no longer valid")

    elif route == "COLLECTOR_INTERNAL":
        if not job.get("collector_id"):
            raise AuthorizationInvalid("SCOUT job missing assigned collector_id")
        cur.execute(
            """
            SELECT
                a.status AS asset_status, a.target_type AS asset_target_type,
                a.normalized_target AS asset_target, a.network_scope AS asset_scope,
                a.collector_id AS asset_collector_id,
                au.status AS authorization_status, au.target_type AS authorization_target_type,
                au.normalized_target AS authorization_target, au.network_scope AS authorization_scope,
                au.approved_at, au.expires_at,
                c.enrollment_status AS collector_enrollment_status,
                c.operator_status AS collector_operator_status
            FROM assets a
            JOIN asset_scan_authorizations au
              ON au.tenant_id = a.tenant_id AND au.asset_id = a.id
            JOIN collectors c
              ON c.tenant_id = a.tenant_id AND c.id = a.collector_id
            WHERE a.tenant_id = %s AND a.id = %s AND au.id = %s AND c.id = %s
            FOR UPDATE OF a, au, c
            """,
            (
                str(job["tenant_id"]),
                str(job["asset_id"]),
                str(job["authorization_id"]),
                str(job["collector_id"]),
            ),
        )
        current = cur.fetchone()
        valid = current and (
            current["asset_status"] == "active"
            and current["asset_scope"] == "internal"
            and str(current["asset_collector_id"]) == str(job["collector_id"])
            and current["collector_enrollment_status"] == "enrolled"
            and current["collector_operator_status"] == "active"
            and current["authorization_status"] == "approved"
            and current["expires_at"] is not None
            and current["expires_at"] > now
            and current["asset_target_type"] == job["target_type"]
            and current["asset_target"] == job["normalized_target"]
            and current["asset_scope"] == job["network_scope"]
            and current["authorization_target_type"] == job["target_type"]
            and current["authorization_target"] == job["normalized_target"]
            and current["authorization_scope"] == job["network_scope"]
            and current["approved_at"] == job["authorization_approved_at"]
            and current["expires_at"] == job["authorization_expires_at"]
        )
        if not valid:
            raise AuthorizationInvalid("Current exact-target authorization or collector assignment is no longer valid")
    else:
        raise AuthorizationInvalid(f"Unsupported SCOUT job route {route}")


def _authorized_run(job: dict, argv: list[str], timeout: int) -> ProcessResult:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            _validate_locked(cur, job)
            # Commit only after Popen succeeds: locks close the validation-to-spawn race.
            return run_bounded(argv, timeout, on_started=conn.commit)


def _assert_authorized(job: dict) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            _validate_locked(cur, job)
        conn.commit()


def _fail_job(job: dict, code: str, message: str) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scout_jobs
                SET status = 'failed', error_code = %s, error_message = %s, completed_at = now()
                WHERE id = %s AND tenant_id = %s AND status IN ('queued', 'running')
                """,
                (code, message, str(job["id"]), str(job["tenant_id"])),
            )
        conn.commit()


def _create_tool_run(job: dict, probe: ToolProbe, ordinal: int) -> uuid.UUID:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scout_tool_runs (
                    tenant_id, job_id, engine, ordinal, state, executable_path,
                    engine_version, templates_version, exit_code, stderr, completed_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    CASE WHEN %s = 'available' THEN NULL ELSE now() END)
                RETURNING id
                """,
                (
                    str(job["tenant_id"]), str(job["id"]), probe.engine, ordinal,
                    probe.state, probe.executable, probe.engine_version,
                    probe.templates_version, probe.returncode, probe.stderr,
                    probe.state,
                ),
            )
            tool_run_id = cur.fetchone()["id"]
        conn.commit()
    return tool_run_id


def _finish_tool_run(
    job: dict,
    tool_run_id: uuid.UUID,
    result: ProcessResult,
    observations: Optional[list[tuple[str, dict]]] = None,
    normalize_nuclei: bool = False,
    parse_stats: Optional[dict] = None,
    sanitized_excerpt: Optional[str] = None,
) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            for kind, evidence in observations or []:
                cur.execute(
                    """
                    INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                    VALUES (%s, %s, %s, %s, %s) RETURNING id
                    """,
                    (str(job["tenant_id"]), str(job["id"]), str(tool_run_id), kind, Jsonb(evidence)),
                )
                observation_id = cur.fetchone()["id"]
                if normalize_nuclei:
                    _normalize_nuclei_observation(conn, job, observation_id)
            cur.execute(
                """
                UPDATE scout_tool_runs
                SET state = %s, exit_code = %s, stderr = %s,
                    stdout_bytes = %s, stderr_bytes = %s,
                    sanitized_output_excerpt = COALESCE(%s, sanitized_output_excerpt),
                    parse_stats = COALESCE(%s, parse_stats),
                    started_at = COALESCE(started_at, now()), completed_at = now()
                WHERE id = %s AND tenant_id = %s AND job_id = %s
                """,
                (
                    result.state, result.returncode,
                    result.stderr.decode("utf-8", errors="replace"),
                    len(result.stdout), len(result.stderr),
                    sanitized_excerpt, Jsonb(parse_stats) if parse_stats is not None else None,
                    str(tool_run_id),
                    str(job["tenant_id"]), str(job["id"]),
                ),
            )
        conn.commit()


def _fail_tool_run(
    job: dict,
    tool_run_id: uuid.UUID,
    state: str = "failed",
    exit_code: Optional[int] = None,
    stdout_bytes: int = 0,
    stderr_bytes: int = 0,
    error_message: Optional[str] = None,
    started_at: Optional[str] = None,
    completed_at: Optional[str] = None,
) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scout_tool_runs
                SET state = %s, exit_code = %s,
                    stdout_bytes = %s, stderr_bytes = %s,
                    stderr = %s,
                    started_at = COALESCE(%s::timestamptz, started_at),
                    completed_at = COALESCE(%s::timestamptz, now())
                WHERE id = %s AND tenant_id = %s AND job_id = %s
                """,
                (
                    state,
                    exit_code,
                    stdout_bytes,
                    stderr_bytes,
                    error_message or "",
                    started_at or None,
                    completed_at or None,
                    str(tool_run_id),
                    str(job["tenant_id"]),
                    str(job["id"]),
                ),
            )
        conn.commit()


def _execute_central_job(job: dict) -> None:
    probes: dict[str, ToolProbe] = {}
    tool_runs: dict[str, uuid.UUID] = {}
    try:
        for ordinal, engine in enumerate(PROFILE_ENGINES[job["profile"]], start=1):
            _assert_authorized(job)
            probe = probe_tool(engine, runner=lambda argv, timeout: _authorized_run(job, argv, timeout))
            probes[engine] = probe
            tool_runs[engine] = _create_tool_run(job, probe, ordinal)
    except AuthorizationInvalid as exc:
        _fail_job(job, "authorization_invalid", str(exc))
        return

    unavailable = next((probe for probe in probes.values() if not probe.available), None)
    if unavailable:
        code = "tool_unavailable" if unavailable.state == "unavailable" else "tool_probe_failed"
        _fail_job(job, code, f"{unavailable.engine} probe: {unavailable.state}")
        return

    for engine in PROFILE_ENGINES[job["profile"]]:
        probe = probes[engine]
        if engine == "nuclei":
            # Authorization is evaluated before the templates refusal so the
            # barrier test semantics are unchanged for unauthorized targets.
            try:
                _assert_authorized(job)
                templates_dir = resolve_scout_nuclei_templates_dir()
            except AuthorizationInvalid as exc:
                _fail_job(job, "authorization_invalid", str(exc))
                return
            except ScoutTemplatesUnavailable as exc:
                _fail_job(job, "nuclei_templates_unavailable", str(exc))
                return
            argv = nuclei_argv(probe.executable, job["normalized_target"], templates_dir)
        else:
            argv = nmap_argv(probe.executable, job["normalized_target"])
        timeout = NMAP_TIMEOUT if engine == "nmap" else NUCLEI_TIMEOUT
        try:
            result = _authorized_run(job, argv, timeout)
        except AuthorizationInvalid as exc:
            _fail_job(job, "authorization_invalid", str(exc))
            return
        if result.state != "succeeded":
            _finish_tool_run(job, tool_runs[engine], result)
            _fail_job(job, f"tool_{result.state}", f"{engine} scan: {result.state}")
            return
        parse_stats = None
        sanitized_excerpt = None
        try:
            if engine == "nmap":
                observations = parse_nmap_xml(result.stdout)
            else:
                observations, parse_stats = parse_nuclei_jsonl_with_stats(result.stdout)
                sanitized_excerpt = _sanitize_nuclei_stdout(result.stdout.decode("utf-8", errors="replace"))
        except (ET.ParseError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            parse_result = ProcessResult("parse_failed", result.returncode, result.stdout, str(exc).encode())
            _finish_tool_run(job, tool_runs[engine], parse_result)
            _fail_job(job, "parse_failed", f"{engine} output was malformed")
            return
        try:
            _finish_tool_run(
                job,
                tool_runs[engine],
                result,
                observations,
                normalize_nuclei=engine == "nuclei",
                parse_stats=parse_stats,
                sanitized_excerpt=sanitized_excerpt,
            )
        except Exception:
            if engine != "nuclei":
                raise
            _finish_tool_run(job, tool_runs[engine], ProcessResult("failed", result.returncode, b"", b""))
            _fail_job(job, "normalization_failed", "Nuclei evidence normalization failed")
            return

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scout_jobs
                SET status = 'succeeded', completed_at = now(), error_code = NULL, error_message = NULL
                WHERE id = %s AND tenant_id = %s AND status = 'running'
                """,
                (str(job["id"]), str(job["tenant_id"])),
            )
        conn.commit()


async def _execute_collector_job(job: dict) -> None:
    from app.collector_registry import collector_registry

    collector_id_raw = job.get("collector_id")
    if not collector_id_raw:
        _fail_job(job, "asset_missing_collector_assignment", "No collector assigned to internal asset")
        return
    collector_id = uuid.UUID(str(collector_id_raw))

    if not collector_registry.is_connected(collector_id):
        _fail_job(job, "collector_offline", "Assigned collector is offline")
        return

    caps = collector_registry.get_collector_capabilities(collector_id) or {}
    required_engines = PROFILE_ENGINES[job["profile"]]
    for engine in required_engines:
        cap = caps.get(engine) if isinstance(caps, dict) else None
        if not cap or not cap.get("available"):
            _fail_job(
                job,
                "collector_missing_engine_capability",
                f"Assigned collector lacks required engine '{engine}'"
            )
            return

    tool_runs: dict[str, uuid.UUID] = {}
    for ordinal, engine in enumerate(required_engines, start=1):
        cap = caps.get(engine, {}) if isinstance(caps, dict) else {}
        probe = ToolProbe(
            engine=engine,
            state="available",
            executable=None,
            engine_version=cap.get("version"),
            templates_version=cap.get("templates_version"),
        )
        tool_runs[engine] = _create_tool_run(job, probe, ordinal)

    for engine in required_engines:
        try:
            _assert_authorized(job)
        except AuthorizationInvalid as exc:
            _fail_tool_run(job, tool_runs[engine], state="failed", error_message="authorization_invalid")
            _fail_job(job, "authorization_invalid", str(exc))
            return

        timeout = NMAP_TIMEOUT if engine == "nmap" else NUCLEI_TIMEOUT
        raw_result = await collector_registry.dispatch_scout_job(
            collector_id=collector_id,
            tenant_id=uuid.UUID(str(job["tenant_id"])),
            job_id=uuid.UUID(str(job["id"])),
            engine=engine,
            profile=job["profile"],
            target=job["normalized_target"],
            target_type=job["target_type"],
            network_scope=job["network_scope"],
            timeout_seconds=timeout,
            expires_at_dt=job["authorization_expires_at"],
        )

        if raw_result.get("error_code") == "collector_disconnected":
            _fail_tool_run(job, tool_runs[engine], state="failed", error_message="collector_disconnected")
            _fail_job(job, "collector_disconnected", raw_result.get("error_message", "Collector disconnected during scan"))
            return

        if _is_collector_timeout(raw_result):
            _fail_tool_run(
                job,
                tool_runs[engine],
                state="timed_out",
                exit_code=raw_result.get("exit_code"),
                stdout_bytes=int(raw_result.get("stdout_bytes") or 0),
                stderr_bytes=int(raw_result.get("stderr_bytes") or 0),
                error_message=collector_timeout_detail(engine, raw_result),
                started_at=raw_result.get("started_at") or None,
                completed_at=raw_result.get("completed_at") or None,
            )
            _fail_job(job, "collector_timeout", collector_timeout_message(engine, raw_result))
            return

        if raw_result.get("status") != "completed":
            exit_code = raw_result.get("exit_code")
            err_msg = raw_result.get("error_message", f"{engine} scan failed")
            _fail_tool_run(job, tool_runs[engine], state="failed", exit_code=exit_code, error_message=err_msg)
            _fail_job(job, "tool_failed", err_msg)
            return

        stdout_raw = raw_result.get("stdout", "")
        stdout_bytes = stdout_raw.encode("utf-8") if isinstance(stdout_raw, str) else stdout_raw
        parse_stats = None
        sanitized_excerpt = None
        try:
            if engine == "nmap":
                observations = parse_nmap_xml(stdout_bytes)
            else:
                observations, parse_stats = parse_nuclei_jsonl_with_stats(stdout_bytes)
                sanitized_excerpt = _sanitize_nuclei_stdout(
                    stdout_bytes.decode("utf-8", errors="replace")
                )
        except (ET.ParseError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            _fail_tool_run(
                job,
                tool_runs[engine],
                state="parse_failed",
                exit_code=raw_result.get("exit_code", 0),
                stdout_bytes=raw_result.get("stdout_bytes", len(stdout_bytes)),
                stderr_bytes=raw_result.get("stderr_bytes", 0),
                error_message=f"{engine} output was malformed: {exc}"
            )
            _fail_job(job, "parse_failed", f"{engine} output was malformed")
            return

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    try:
                        _validate_locked(cur, job)
                    except AuthorizationInvalid as exc:
                        conn.rollback()
                        _fail_tool_run(job, tool_runs[engine], state="failed", error_message=str(exc))
                        _fail_job(job, "authorization_invalid", str(exc))
                        return

                    for kind, evidence in observations:
                        cur.execute(
                            """
                            INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                            VALUES (%s, %s, %s, %s, %s) RETURNING id
                            """,
                            (str(job["tenant_id"]), str(job["id"]), str(tool_runs[engine]), kind, Jsonb(evidence)),
                        )
                        observation_id = cur.fetchone()["id"]
                        if engine == "nuclei":
                            _normalize_nuclei_observation(conn, job, observation_id)

                    cur.execute(
                        """
                        UPDATE scout_tool_runs
                        SET state = 'succeeded', exit_code = %s,
                            stdout_bytes = %s, stderr_bytes = %s,
                            sanitized_output_excerpt = %s,
                            parse_stats = %s,
                            started_at = COALESCE(started_at, now()), completed_at = now()
                        WHERE id = %s AND tenant_id = %s AND job_id = %s
                        """,
                        (
                            raw_result.get("exit_code", 0),
                            raw_result.get("stdout_bytes", len(stdout_bytes)),
                            raw_result.get("stderr_bytes", 0),
                            sanitized_excerpt,
                            Jsonb(parse_stats) if parse_stats is not None else None,
                            str(tool_runs[engine]),
                            str(job["tenant_id"]),
                            str(job["id"]),
                        ),
                    )
                conn.commit()
        except Exception as exc:
            _fail_tool_run(job, tool_runs[engine], state="failed", error_message="Evidence normalization failed")
            _fail_job(job, "normalization_failed", f"Nuclei evidence normalization failed: {exc}")
            return

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scout_jobs
                SET status = 'succeeded', completed_at = now(), error_code = NULL, error_message = NULL
                WHERE id = %s AND tenant_id = %s AND status = 'running'
                """,
                (str(job["id"]), str(job["tenant_id"])),
            )
        conn.commit()


def execute_job(job_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    job = _job_row(job_id, tenant_id)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scout_jobs SET status = 'running', started_at = now()
                WHERE id = %s AND tenant_id = %s AND status = 'queued'
                RETURNING *
                """,
                (str(job_id), str(tenant_id)),
            )
            claimed = cur.fetchone()
        conn.commit()
    if not claimed:
        return
    job = dict(claimed)

    if job.get("route") == "COLLECTOR_INTERNAL":
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            asyncio.create_task(_execute_collector_job(job))
        else:
            asyncio.run(_execute_collector_job(job))
    else:
        _execute_central_job(job)
