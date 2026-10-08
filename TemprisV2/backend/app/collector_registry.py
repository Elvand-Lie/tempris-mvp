# backend/app/collector_registry.py
import asyncio
import collections
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple, Any
from fastapi import WebSocket
from app.db import get_db_connection
from app.audit import record_audit_event

logger = logging.getLogger("collector_registry")

# The server-side wait for a SCOUT_JOB result must STRICTLY exceed the engine envelope it
# hands the collector. The daemon bounds the engine at that same envelope
# (collector/src/scout_runner.rs: `tokio::time::timeout(effective_timeout, wait_child)`),
# KILLS the engine when it expires, and only THEN emits SCOUT_JOB_RESULT — so this margin
# has to cover engine teardown/reap, up to OUTPUT_LIMIT (4 MiB) of serialized result, and
# the WSS transit back to this process.
#
# It is NOT spare scan time. Widening it does not make a slow engine finish sooner; it only
# stops a slow-but-successful result — or the daemon's own truthful timeout frame — from
# being discarded and misreported as a server-side `Collector scan timed out after Ns`.
#
# Both central and collector Nmap paths now use --host-timeout 120s under a 180s
# envelope. The margin covers result delivery after engine teardown, including
# the daemon's truthful timeout frame if its outer envelope fires instead.
SCOUT_RESULT_GRACE_SECONDS = 30


def _deliver_future_result(future: asyncio.Future, payload: dict) -> None:
    """Complete an in-flight result future on the loop that is waiting for it.

    SCOUT execution runs through ``asyncio.run`` on a worker thread, while the
    collector socket is read on the server loop. ``Future.set_result`` from the
    reader thread marks the future done but does not wake the worker loop, so
    ``wait_for`` only notices the result when its own deadline fires. Scheduling
    the completion on the future's loop delivers it immediately.
    """
    if future.done():
        return

    def _set() -> None:
        if not future.done():
            future.set_result(payload)

    try:
        loop = future.get_loop()
    except RuntimeError:
        return
    try:
        current = asyncio.get_running_loop()
    except RuntimeError:
        current = None
    if current is loop:
        _set()
        return
    try:
        loop.call_soon_threadsafe(_set)
    except RuntimeError:
        return


class CollectorSession:
    def __init__(
        self,
        session_id: Optional[uuid.UUID] = None,
        collector_id: Optional[uuid.UUID] = None,
        tenant_id: Optional[uuid.UUID] = None,
        websocket: Optional[WebSocket] = None,
        operator_status: str = "active",
        clock: Optional[Callable[[], float]] = None
    ):
        self.session_id = session_id or uuid.uuid4()
        self.collector_id = collector_id
        self.tenant_id = tenant_id
        self.websocket = websocket
        self.operator_status = operator_status
        self.connected_at = datetime.now(timezone.utc)
        self.last_heartbeat_at = datetime.now(timezone.utc)
        self.in_flight_jobs: Dict[Any, asyncio.Future] = {}
        self.capabilities: Optional[dict] = None
        self.collector_version: Optional[str] = None
        self.message_timestamps: collections.deque = collections.deque()
        self._clock = clock or time.time

    def get_time(self) -> float:
        return self._clock()

    def record_message(self, timestamp: Optional[float] = None) -> None:
        t = timestamp if timestamp is not None else self.get_time()
        # Clean older than 15 minutes (900 seconds)
        cutoff = t - 900.0
        while self.message_timestamps and self.message_timestamps[0] < cutoff:
            self.message_timestamps.popleft()
        self.message_timestamps.append(t)

    def get_rate(self, timestamp: Optional[float] = None) -> float:
        """Returns message rate per second over current window."""
        t = timestamp if timestamp is not None else self.get_time()
        cutoff = t - 900.0
        while self.message_timestamps and self.message_timestamps[0] < cutoff:
            self.message_timestamps.popleft()

        n = len(self.message_timestamps)
        if n < 2:
            return 0.0

        span = max(1.0, min(900.0, self.message_timestamps[-1] - self.message_timestamps[0]))
        return round(n / span, 2)

    def is_rate_limit_exceeded(self, timestamp: Optional[float] = None) -> bool:
        """
        Sustained rate >= 5.0 msg/s over 15 minutes (900 seconds).
        Triggered when window spans at least 15 minutes (900s) and message count >= 4500 (or rate >= 5.0 msg/s).
        """
        t = timestamp if timestamp is not None else self.get_time()
        cutoff = t - 900.0
        while self.message_timestamps and self.message_timestamps[0] < cutoff:
            self.message_timestamps.popleft()

        n = len(self.message_timestamps)
        if n < 4500:
            return False

        span = self.message_timestamps[-1] - self.message_timestamps[0]
        if span >= 900.0:  # Full 15 minutes window
            rate = n / span
            return rate >= 5.0
        return False

    def fail_all_jobs(self, error_message: str = "Collector disconnected or timed out during verification.") -> None:
        for job_id, future in list(self.in_flight_jobs.items()):
            if not future.done():
                _deliver_future_result(future, {
                    "job_id": str(job_id),
                    "status": "failed",
                    "reachability_status": "unverified",
                    "error_code": "collector_disconnected",
                    "error_message": error_message
                })
        self.in_flight_jobs.clear()

        # Update in-flight scout_jobs to collector_disconnected
        if self.tenant_id and self.collector_id:
            try:
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE scout_jobs
                            SET status = 'failed',
                                error_code = 'collector_disconnected',
                                error_message = 'Collector disconnected during scan',
                                completed_at = now()
                            WHERE tenant_id = %s
                              AND collector_id = %s
                              AND status = 'running';
                            """,
                            (str(self.tenant_id), str(self.collector_id))
                        )
                    conn.commit()
            except Exception as e:
                logger.warning("Error marking running scout_jobs as collector_disconnected: %s", e)


class CollectorRegistry:
    def __init__(self, clock: Optional[Callable[[], float]] = None):
        self._sessions: Dict[uuid.UUID, CollectorSession] = {}
        self._challenges: Dict[str, dict] = {}  # session_key -> challenge data
        self._clock = clock or time.time

    def set_clock(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        for s in self._sessions.values():
            s._clock = clock

    def register_challenge(self, session_key: str, nonce: str, expires_at: str, expires_at_dt: datetime) -> None:
        self._challenges[session_key] = {
            "nonce": nonce,
            "expires_at": expires_at,
            "expires_at_dt": expires_at_dt,
            "used": False
        }

    def consume_challenge(self, session_key: str, nonce: str, expires_at: str) -> Tuple[bool, Optional[str]]:
        """
        Validates challenge nonce & expiry.
        Strict single-use: immediately marks nonce used on first check.
        Returns (is_valid, error_reason).
        """
        challenge = self._challenges.get(session_key)
        if not challenge:
            return False, "No active challenge for session"

        if challenge["used"]:
            return False, "Challenge nonce already consumed (replay detected)"

        # Mark consumed immediately
        challenge["used"] = True

        if challenge["nonce"] != nonce:
            return False, "Challenge nonce mismatch"

        if challenge["expires_at"] != expires_at:
            return False, "Challenge expires_at mismatch"

        now_utc = datetime.now(timezone.utc)
        if now_utc > challenge["expires_at_dt"]:
            return False, "Challenge has expired"

        return True, None

    def clear_challenge(self, session_key: str) -> None:
        self._challenges.pop(session_key, None)

    def register_session(
        self,
        collector_id: uuid.UUID,
        tenant_id: uuid.UUID,
        websocket: WebSocket,
        operator_status: str = "active"
    ) -> CollectorSession:
        # If an existing session exists for this collector, disconnect it cleanly
        if collector_id in self._sessions:
            old_session = self._sessions[collector_id]
            old_session.fail_all_jobs("Collector reconnected from a new session.")
            try:
                asyncio.create_task(old_session.websocket.close(code=1008, reason="Replaced by new connection"))
            except Exception:
                pass

        new_session_id = uuid.uuid4()
        session = CollectorSession(
            session_id=new_session_id,
            collector_id=collector_id,
            tenant_id=tenant_id,
            websocket=websocket,
            operator_status=operator_status,
            clock=self._clock
        )

        if websocket and hasattr(websocket, "receive_text"):
            orig_receive_text = websocket.receive_text
            async def intercepted_receive_text():
                while True:
                    msg = await orig_receive_text()
                    try:
                        parsed = json.loads(msg)
                        if isinstance(parsed, dict):
                            f_type = parsed.get("type")
                            if f_type == "SCOUT_CAPABILITIES":
                                caps = parsed.get("capabilities") or {}
                                session.capabilities = caps
                                try:
                                    from app.toolchain_checks import complete_check
                                    complete_check(collector_id, caps)
                                except Exception:
                                    pass
                                col_ver = caps.get("collector_version")
                                if col_ver and isinstance(col_ver, str):
                                    sanitized_ver = "".join(c for c in col_ver if c.isalnum() or c in ".-_")[:64]
                                    if sanitized_ver:
                                        session.collector_version = sanitized_ver
                                        self._persist_collector_version(collector_id, sanitized_ver)
                                continue
                            elif f_type == "SCOUT_JOB_RESULT":
                                self.handle_scout_job_result(collector_id, parsed, session_id=session.session_id)
                                continue
                            elif f_type == "HEARTBEAT" and "capabilities" in parsed:
                                session.capabilities = parsed["capabilities"]
                                if isinstance(parsed["capabilities"], dict):
                                    col_ver = parsed["capabilities"].get("collector_version")
                                    if col_ver and isinstance(col_ver, str):
                                        sanitized_ver = "".join(c for c in col_ver if c.isalnum() or c in ".-_")[:64]
                                        if sanitized_ver:
                                            session.collector_version = sanitized_ver
                                            self._persist_collector_version(collector_id, sanitized_ver)
                    except Exception:
                        pass
                    return msg
            websocket.receive_text = intercepted_receive_text

        self._sessions[collector_id] = session
        return session

    def unregister_session(
        self,
        collector_id: uuid.UUID,
        session_id: Optional[uuid.UUID] = None,
        reason: Optional[str] = None
    ) -> Optional[CollectorSession]:
        if collector_id in self._sessions:
            current_session = self._sessions[collector_id]
            if session_id is not None and current_session.session_id != session_id:
                logger.debug(
                    "Ignoring unregister for superseded session %s on collector %s (current: %s)",
                    session_id, collector_id, current_session.session_id
                )
                return None
            session = self._sessions.pop(collector_id, None)
            if session:
                session.fail_all_jobs(reason or "Collector disconnected or timed out during verification.")
                try:
                    from app.toolchain_checks import fail_pending_check
                    fail_pending_check(collector_id, reason or "Collector disconnected mid-check.")
                except Exception:
                    pass
            return session
        return None

    def get_session(self, collector_id: uuid.UUID) -> Optional[CollectorSession]:
        return self._sessions.get(collector_id)

    def is_connected(self, collector_id: uuid.UUID) -> bool:
        session = self._sessions.get(collector_id)
        if not session:
            return False
        # Connected means socket registered and heartbeat seen in last 60 seconds
        now_utc = datetime.now(timezone.utc)
        return (now_utc - session.last_heartbeat_at).total_seconds() < 60.0

    def record_heartbeat(self, collector_id: uuid.UUID, session_id: Optional[uuid.UUID] = None) -> bool:
        session = self._sessions.get(collector_id)
        if session:
            if session_id is not None and session.session_id != session_id:
                return False
            session.last_heartbeat_at = datetime.now(timezone.utc)
            return True
        return False

    def get_rate(self, collector_id: uuid.UUID) -> float:
        session = self._sessions.get(collector_id)
        if session:
            return session.get_rate()
        return 0.0

    def get_connection_status(self, collector_id: uuid.UUID) -> str:
        return "connected" if self.is_connected(collector_id) else "offline"

    def get_derived_status(self, enrollment_status: str, operator_status: str, collector_id: uuid.UUID) -> str:
        if enrollment_status == "awaiting_enrollment":
            return "awaiting_enrollment"
        if operator_status == "paused":
            return "paused"
        if operator_status == "quarantined":
            return "quarantined"
        if operator_status == "revoked":
            return "revoked"
        if enrollment_status == "enrolled" and operator_status == "active":
            return "connected" if self.is_connected(collector_id) else "offline"
        return operator_status.lower()

    def update_operator_status(self, collector_id: uuid.UUID, operator_status: str) -> None:
        session = self._sessions.get(collector_id)
        if session:
            session.operator_status = operator_status

    async def terminate_socket(self, collector_id: uuid.UUID, close_code: int = 1008, reason: str = "Policy violation") -> None:
        session = self.unregister_session(collector_id, reason=reason)
        if session:
            try:
                await session.websocket.close(code=close_code, reason=reason)
            except Exception:
                pass

    async def terminate_tenant_sessions(
        self,
        tenant_id: uuid.UUID,
        close_code: int = 1008,
        reason: str = "Tenant disabled"
    ) -> List[uuid.UUID]:
        """
        Terminates all active collector sessions for the given tenant.
        1. Filters active sessions where session.tenant_id == tenant_id.
        2. Fails in-flight jobs with unverified reachability status.
        3. Closes WebSockets with close_code (default 1008).
        4. Safely unregisters sessions from registry.
        Returns list of terminated collector IDs.
        """
        terminated_ids: List[uuid.UUID] = []
        matching_sessions = [s for s in list(self._sessions.values()) if s.tenant_id == tenant_id]

        for session in matching_sessions:
            if session.collector_id:
                terminated_ids.append(session.collector_id)
                session.fail_all_jobs(error_message=reason)
                try:
                    if session.websocket:
                        await session.websocket.close(code=close_code, reason=reason)
                except Exception:
                    pass
                finally:
                    self.unregister_session(
                        session.collector_id,
                        session_id=session.session_id,
                        reason=reason
                    )

        return terminated_ids

    async def dispatch_verify_target(
        self,
        collector_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target_type: str,
        target_value: str,
        normalized_target: str,
        network_scope: str,
        asset_id: Optional[uuid.UUID] = None,
        correlation_id: Optional[str] = None,
        timeout_seconds: float = 8.0,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
    ) -> dict:
        session = self.get_session(collector_id)
        if not session or not self.is_connected(collector_id):
            return {
                "reachability_status": "unverified",
                "error_message": "Collector unavailable; asset remains valid and reachability is unverified."
            }

        if session.operator_status != "active":
            return {
                "reachability_status": "unverified",
                "error_message": f"Collector is {session.operator_status}; asset remains valid and reachability is unverified."
            }

        job_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        session.in_flight_jobs[job_id] = future

        expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=int(timeout_seconds))
        expires_at_str = expires_at_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            "type": "VERIFY_TARGET",
            "operation": "VERIFY_TARGET",
            "job_id": job_id,
            "asset_id": str(asset_id) if asset_id else None,
            "correlation_id": correlation_id,
            "target": normalized_target,
            "target_value": target_value,
            "target_type": target_type,
            "network_scope": network_scope,
            "expires_at": expires_at_str,
            "timeout_seconds": int(timeout_seconds)
        }

        # Emit collector.job_dispatched audit event
        try:
            with get_db_connection() as conn:
                record_audit_event(
                    conn=conn,
                    tenant_id=tenant_id,
                    actor_id=actor_id or "system:registry",
                    actor_role=actor_role or "system",
                    event_name="collector.job_dispatched",
                    asset_id=asset_id,
                    details={
                        "collector_id": str(collector_id),
                        "job_id": job_id,
                        "operation": "VERIFY_TARGET",
                        "target_type": target_type,
                        "normalized_target": normalized_target,
                        "network_scope": network_scope,
                    }
                )
                conn.commit()
        except Exception as e:
            logger.warning("Failed to record job_dispatched audit event: %s", e)

        try:
            await session.websocket.send_text(json.dumps(payload))
            result = await asyncio.wait_for(future, timeout=timeout_seconds)

            res_status = result.get("status", "completed")
            is_success = (
                res_status in ("success", "completed")
                and result.get("reachability_status") in ("verified", "unreachable")
                and not result.get("error_message")
            )
            event_name = "collector.job_completed" if is_success else "collector.job_rejected"

            try:
                with get_db_connection() as conn:
                    record_audit_event(
                        conn=conn,
                        tenant_id=tenant_id,
                        actor_id=f"collector:{str(collector_id)}",
                        actor_role="collector",
                        event_name=event_name,
                        asset_id=asset_id,
                        details={
                            "collector_id": str(collector_id),
                            "job_id": job_id,
                            "status": res_status,
                            "reachable": result.get("reachable", False),
                            "method": result.get("method", "tcp_probe"),
                            "port": result.get("port") or result.get("port_reached"),
                            "started_at": result.get("started_at"),
                            "completed_at": result.get("completed_at"),
                        }
                    )
                    conn.commit()
            except Exception as e:
                logger.warning("Failed to record %s audit event: %s", event_name, e)

            return result
        except asyncio.TimeoutError:
            session.in_flight_jobs.pop(job_id, None)
            try:
                with get_db_connection() as conn:
                    record_audit_event(
                        conn=conn,
                        tenant_id=tenant_id,
                        actor_id="system:registry",
                        actor_role="system",
                        event_name="collector.job_rejected",
                        asset_id=asset_id,
                        details={
                            "collector_id": str(collector_id),
                            "job_id": job_id,
                            "reason": "timeout"
                        }
                    )
                    conn.commit()
            except Exception:
                pass
            return {
                "job_id": job_id,
                "status": "failed",
                "reachability_status": "unverified",
                "error_message": "Collector disconnected or timed out during verification."
            }
        except Exception as e:
            session.in_flight_jobs.pop(job_id, None)
            try:
                with get_db_connection() as conn:
                    record_audit_event(
                        conn=conn,
                        tenant_id=tenant_id,
                        actor_id="system:registry",
                        actor_role="system",
                        event_name="collector.job_rejected",
                        asset_id=asset_id,
                        details={
                            "collector_id": str(collector_id),
                            "job_id": job_id,
                            "reason": "error"
                        }
                    )
                    conn.commit()
            except Exception:
                pass
            return {
                "job_id": job_id,
                "status": "failed",
                "reachability_status": "unverified",
                "error_message": "Collector disconnected or timed out during verification."
            }
        finally:
            session.in_flight_jobs.pop(job_id, None)

    def handle_verify_target_result(
        self,
        collector_id: uuid.UUID,
        result_payload: dict,
        session_id: Optional[uuid.UUID] = None
    ) -> bool:
        session = self.get_session(collector_id)
        if not session:
            return False

        if session_id is not None and session.session_id != session_id:
            return False

        job_id = result_payload.get("job_id")
        if not job_id:
            return False

        future = session.in_flight_jobs.pop(job_id, None)
        if future and not future.done():
            _deliver_future_result(future, result_payload)
            return True
        return False

    def get_collector_capabilities(self, collector_id: uuid.UUID) -> Optional[dict]:
        session = self.get_session(collector_id)
        if session:
            return session.capabilities
        return None

    def get_collector_version(self, collector_id: uuid.UUID) -> Optional[str]:
        session = self.get_session(collector_id)
        if session and session.collector_version:
            return session.collector_version
        return None

    def _persist_collector_version(self, collector_id: uuid.UUID, version: str) -> None:
        try:
            from app.db import get_db_connection
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE collectors
                        SET version = %s, updated_at = now()
                        WHERE id = %s
                        """,
                        (version, str(collector_id)),
                    )
                conn.commit()
        except Exception as e:
            logger.debug("Could not persist collector %s version %s to DB: %s", collector_id, version, e)

    @staticmethod
    def _sanitize_network_state(network_state: Any) -> Optional[Tuple[datetime, list]]:
        """Bound and validate a collector-reported location. Returns (observed_at, addresses) or None."""
        import ipaddress
        if not isinstance(network_state, dict):
            return None
        now = datetime.now(timezone.utc)
        observed_at_raw = network_state.get("observed_at")
        if isinstance(observed_at_raw, str) and observed_at_raw:
            try:
                observed_at = datetime.fromisoformat(observed_at_raw.replace("Z", "+00:00"))
            except ValueError:
                observed_at = now
            # Reject implausible clock skew: an observation cannot come from the future.
            if observed_at > now + timedelta(minutes=5):
                observed_at = now
            if observed_at.tzinfo is None:
                observed_at = observed_at.replace(tzinfo=timezone.utc)
        else:
            observed_at = now

        addresses = network_state.get("addresses")
        if not isinstance(addresses, list):
            return None
        cleaned = []
        for entry in addresses[:64]:
            if not isinstance(entry, dict):
                continue
            interface = entry.get("interface")
            ip_raw = entry.get("ip")
            prefix = entry.get("prefix")
            if not isinstance(interface, str) or not interface.strip() or len(interface) > 64:
                continue
            if not isinstance(ip_raw, str):
                continue
            try:
                ip = ipaddress.ip_address(ip_raw)
            except ValueError:
                continue
            if ip.is_unspecified or ip.is_loopback:
                continue
            max_prefix = 32 if ip.version == 4 else 128
            if not isinstance(prefix, int) or isinstance(prefix, bool) or not (0 <= prefix <= max_prefix):
                continue
            cleaned.append({"interface": interface.strip()[:64], "ip": str(ip), "prefix": prefix})
        if not cleaned:
            return None
        return observed_at, cleaned

    def record_network_observation(self, collector_id: uuid.UUID, network_state: Any) -> Optional[dict]:
        """Persist a collector-reported network location (PRD §2.12).

        Location is written ONLY to the explicitly bound host asset — never used
        to infer, create, or rebind identity. Without a binding this is a no-op.
        History is append-only; the CURRENT location advances only monotonically
        (a stale or reordered frame can never roll it back). If the current
        address no longer matches the bound asset's IP target tuple, prior scan
        authorizations are revoked and the asset is flagged for operator
        revalidation — fail-closed, no silent retargeting.
        """
        sanitized = self._sanitize_network_state(network_state)
        if sanitized is None:
            return None
        observed_at, addresses = sanitized
        payload = json.dumps({"observed_at": observed_at.isoformat(), "addresses": addresses})
        try:
            from app.db import get_db_connection
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT b.asset_id, b.tenant_id
                        FROM collector_host_bindings b
                        WHERE b.collector_id = %s
                        """,
                        (str(collector_id),),
                    )
                    binding = cur.fetchone()
                    if not binding:
                        return None

                    cur.execute(
                        """
                        SELECT network_location, target_type, normalized_target,
                               target_validation_state
                        FROM assets
                        WHERE id = %s AND tenant_id = %s
                        FOR UPDATE
                        """,
                        (str(binding["asset_id"]), str(binding["tenant_id"])),
                    )
                    asset = cur.fetchone()
                    if not asset:
                        return None

                    cur.execute(
                        """
                        INSERT INTO asset_network_observations (
                            tenant_id, asset_id, collector_id, network_location, observed_at
                        ) VALUES (%s, %s, %s, %s::jsonb, %s)
                        """,
                        (
                            str(binding["tenant_id"]), str(binding["asset_id"]),
                            str(collector_id), payload, observed_at,
                        ),
                    )

                    # Monotonic current: history keeps everything, current never regresses.
                    current = asset["network_location"] if isinstance(asset["network_location"], dict) else None
                    current_observed_at = None
                    if current and isinstance(current.get("observed_at"), str):
                        try:
                            current_observed_at = datetime.fromisoformat(current["observed_at"].replace("Z", "+00:00"))
                        except ValueError:
                            current_observed_at = None
                    advances = current_observed_at is None or observed_at >= current_observed_at
                    if advances:
                        cur.execute(
                            """
                            UPDATE assets
                            SET network_location = %s::jsonb, updated_at = now()
                            WHERE id = %s AND tenant_id = %s
                            """,
                            (payload, str(binding["asset_id"]), str(binding["tenant_id"])),
                        )

                        # Fail-closed: a bound host whose current IP no longer matches
                        # its IP target tuple must not keep scanning the old address —
                        # that address may now belong to a different occupant.
                        mismatch = None
                        if asset["target_type"] == "ip":
                            current_ips = {address["ip"] for address in addresses}
                            mismatch = asset["normalized_target"] not in current_ips
                            desired_state = "needs_revalidation" if mismatch else "ok"
                            if asset["target_validation_state"] != desired_state:
                                cur.execute(
                                    """
                                    UPDATE assets
                                    SET target_validation_state = %s, updated_at = now()
                                    WHERE id = %s AND tenant_id = %s
                                    """,
                                    (desired_state, str(binding["asset_id"]), str(binding["tenant_id"])),
                                )
                                if mismatch:
                                    cur.execute(
                                        """
                                        UPDATE asset_scan_authorizations
                                        SET status = 'revoked',
                                            revoked_by = 'system:identity_guard',
                                            revoked_at = now(),
                                            revocation_reason =
                                                'Bound host reported a network location that no longer matches its IP target; operator must confirm the target and re-approve'
                                        WHERE asset_id = %s AND tenant_id = %s
                                          AND status IN ('pending', 'approved');
                                        """,
                                        (str(binding["asset_id"]), str(binding["tenant_id"])),
                                    )
                                    record_audit_event(
                                        conn=conn,
                                        tenant_id=binding["tenant_id"],
                                        actor_id="system:identity_guard",
                                        actor_role="system",
                                        event_name="asset.target_revalidation_required",
                                        details={
                                            "asset_id": str(binding["asset_id"]),
                                            "collector_id": str(collector_id),
                                            "reported_addresses": sorted(current_ips),
                                            "asset_target": asset["normalized_target"],
                                        }
                                    )
                conn.commit()
            return {"asset_id": str(binding["asset_id"]), "target_mismatch": mismatch if advances else None}
        except Exception as e:
            logger.debug("Could not record network observation for collector %s: %s", collector_id, e)
            return None

    def handle_scout_job_result(
        self,
        collector_id: uuid.UUID,
        result_payload: dict,
        session_id: Optional[uuid.UUID] = None
    ) -> bool:
        session = self.get_session(collector_id)
        if not session:
            logger.warning("unmatched_scout_job_result: collector %s has no active session", collector_id)
            return False

        if session_id is not None and session.session_id != session_id:
            logger.warning("unmatched_scout_job_result: session_id mismatch for collector %s", collector_id)
            return False

        job_id_raw = result_payload.get("job_id")
        if not job_id_raw:
            logger.warning("unmatched_scout_job_result: missing job_id in payload")
            return False

        try:
            job_uuid = uuid.UUID(str(job_id_raw))
        except ValueError:
            job_uuid = None

        # Atomic pop replay guard
        future = session.in_flight_jobs.pop(job_uuid, None) if job_uuid else None
        future_str = session.in_flight_jobs.pop(str(job_id_raw), None)
        matched_future = future or future_str

        if not matched_future or matched_future.done():
            logger.warning(
                "unmatched_scout_job_result: job %s not found in session %s in_flight_jobs or already resolved",
                job_id_raw, session.session_id
            )
            return False

        _deliver_future_result(matched_future, result_payload)
        return True

    async def dispatch_scout_job(
        self,
        collector_id: uuid.UUID,
        tenant_id: uuid.UUID,
        job_id: uuid.UUID,
        engine: str,
        profile: str,
        target: str,
        target_type: str,
        network_scope: str,
        timeout_seconds: int = 180,
        expires_at_dt: Optional[datetime] = None,
    ) -> dict:
        session = self.get_session(collector_id)
        if not session or not self.is_connected(collector_id):
            return {
                "job_id": str(job_id),
                "engine": engine,
                "status": "failed",
                "error_code": "collector_disconnected",
                "error_message": "Collector is not connected"
            }
        if session.tenant_id != tenant_id:
            return {
                "job_id": str(job_id),
                "engine": engine,
                "status": "failed",
                "error_code": "tenant_mismatch",
                "error_message": "Collector does not belong to the requested tenant"
            }
        if session.operator_status != "active":
            return {
                "job_id": str(job_id),
                "engine": engine,
                "status": "failed",
                "error_code": "collector_inactive",
                "error_message": f"Collector operator status is {session.operator_status}"
            }

        job_uuid = uuid.UUID(str(job_id))
        job_str = str(job_uuid)

        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        session.in_flight_jobs[job_uuid] = future
        session.in_flight_jobs[job_str] = future

        if not expires_at_dt:
            expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=int(timeout_seconds))
        expires_at_str = expires_at_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            "type": "SCOUT_JOB",
            "job_id": job_str,
            "engine": engine,
            "profile": profile,
            "target": target,
            "target_type": target_type,
            "network_scope": network_scope,
            "timeout_seconds": int(timeout_seconds),
            "expires_at": expires_at_str,
        }

        try:
            await session.websocket.send_text(json.dumps(payload))
        except Exception as e:
            session.in_flight_jobs.pop(job_uuid, None)
            session.in_flight_jobs.pop(job_str, None)
            return {
                "job_id": job_str,
                "engine": engine,
                "status": "failed",
                "error_code": "collector_disconnected",
                "error_message": f"Failed to send frame to collector: {e}"
            }

        grace_period = SCOUT_RESULT_GRACE_SECONDS
        total_timeout = int(timeout_seconds) + grace_period
        try:
            result = await asyncio.wait_for(future, timeout=total_timeout)
            return result
        except asyncio.TimeoutError:
            session.in_flight_jobs.pop(job_uuid, None)
            session.in_flight_jobs.pop(job_str, None)
            return {
                "job_id": job_str,
                "engine": engine,
                "status": "failed",
                "error_code": "collector_timeout",
                "error_message": (
                    f"collector_transport_timeout: no result frame within {total_timeout}s "
                    f"(envelope {int(timeout_seconds)}s + grace {grace_period}s)"
                ),
            }
        finally:
            session.in_flight_jobs.pop(job_uuid, None)
            session.in_flight_jobs.pop(job_str, None)

    def strike_capability_ready(self, collector_id: uuid.UUID, capability: str) -> bool:
        """Fail-closed readiness: the collector must have reported the
        capability explicitly available. An unknown/absent report is NOT
        ready (older collectors must upgrade their capability report before
        STRIKE runs dispatch to them)."""
        caps = self.get_collector_capabilities(collector_id)
        if not isinstance(caps, dict):
            return False
        entry = caps.get(capability)
        if not isinstance(entry, dict):
            return False
        return entry.get("available") is True

    async def dispatch_strike_job(
        self,
        collector_id: uuid.UUID,
        tenant_id: uuid.UUID,
        job_id: uuid.UUID,
        method: Optional[str] = None,
        url: Optional[str] = None,
        pinned_ips: Optional[List[str]] = None,
        timeout_seconds: int = 60,
        *,
        capability: str = "curl",
        pinned_targets: Optional[List[str]] = None,
        record_type: Optional[str] = None,
    ) -> dict:
        """Dispatch a STRIKE toolbox run to the user-selected collector over
        the authenticated WSS and await its bounded result. Mirrors the
        SCOUT_JOB dispatch: one in-flight future resolved by the matching
        STRIKE_JOB_RESULT frame (or by fail_all_jobs on disconnect).

        The frame stays backward-compatible: a curl run carries exactly the
        fields it always has; the other Phase-1 tools add capability-specific
        fields (pinned_targets for nmap, record_type for dig) and omit the
        HTTP-only ones."""
        pinned_ips = list(pinned_ips or [])
        session = self.get_session(collector_id)
        if not session or not self.is_connected(collector_id):
            return {
                "job_id": str(job_id),
                "status": "failed",
                "error_code": "collector_disconnected",
                "error_message": "The selected collector is not connected",
            }
        if session.tenant_id != tenant_id:
            return {
                "job_id": str(job_id),
                "status": "failed",
                "error_code": "tenant_mismatch",
                "error_message": "Collector does not belong to the requested tenant",
            }
        if session.operator_status != "active":
            return {
                "job_id": str(job_id),
                "status": "failed",
                "error_code": "collector_inactive",
                "error_message": f"Collector operator status is {session.operator_status}",
            }

        job_uuid = uuid.UUID(str(job_id))
        job_str = str(job_uuid)

        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        session.in_flight_jobs[job_uuid] = future
        session.in_flight_jobs[job_str] = future

        expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=int(timeout_seconds))
        expires_at_str = expires_at_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            "type": "STRIKE_JOB",
            "job_id": job_str,
            "capability": capability,
            "timeout_seconds": int(timeout_seconds),
            "expires_at": expires_at_str,
        }
        if method is not None:
            payload["method"] = method
        if url is not None:
            payload["url"] = url
        payload["pinned_ips"] = list(pinned_ips)
        if pinned_targets is not None:
            payload["pinned_targets"] = list(pinned_targets)
        if record_type is not None:
            payload["record_type"] = record_type

        try:
            await session.websocket.send_text(json.dumps(payload))
        except Exception as e:
            session.in_flight_jobs.pop(job_uuid, None)
            session.in_flight_jobs.pop(job_str, None)
            return {
                "job_id": job_str,
                "status": "failed",
                "error_code": "collector_unreachable",
                "error_message": f"Failed to send STRIKE job to collector: {e}"
            }

        total_timeout = int(timeout_seconds) + SCOUT_RESULT_GRACE_SECONDS
        try:
            return await asyncio.wait_for(future, timeout=total_timeout)
        except asyncio.TimeoutError:
            session.in_flight_jobs.pop(job_uuid, None)
            session.in_flight_jobs.pop(job_str, None)
            return {
                "job_id": job_str,
                "status": "failed",
                "error_code": "collector_timeout",
                "error_message": f"Collector run timed out after {total_timeout}s",
            }
        finally:
            session.in_flight_jobs.pop(job_uuid, None)
            session.in_flight_jobs.pop(job_str, None)

    def handle_strike_job_result(
        self,
        collector_id: uuid.UUID,
        result_payload: dict,
        session_id: Optional[uuid.UUID] = None
    ) -> bool:
        session = self.get_session(collector_id)
        if not session:
            return False
        if session_id is not None and session.session_id != session_id:
            return False
        job_id_raw = result_payload.get("job_id")
        if not job_id_raw:
            return False
        try:
            job_uuid = uuid.UUID(str(job_id_raw))
        except ValueError:
            job_uuid = None
        future = session.in_flight_jobs.pop(job_uuid, None) if job_uuid else None
        future_str = session.in_flight_jobs.pop(str(job_id_raw), None)
        matched = future or future_str
        if not matched or matched.done():
            return False
        _deliver_future_result(matched, result_payload)
        return True

    async def dispatch_check_update(
        self,
        collector_id: uuid.UUID,
        tenant_id: uuid.UUID,
        force_recheck: bool = False,
        check_id: Optional[str] = None,
    ) -> bool:
        session = self.get_session(collector_id)
        if not session or not self.is_connected(collector_id):
            return False
        if session.tenant_id != tenant_id:
            return False

        # Typed ServerFrame::CHECK_UPDATE carrying strictly check_id and force_recheck (Anti-RCE B.1, B.2)
        payload = {
            "type": "CHECK_UPDATE",
            "check_id": check_id or str(uuid.uuid4()),
            "force_recheck": force_recheck,
        }
        try:
            await session.websocket.send_text(json.dumps(payload))
            return True
        except Exception as e:
            logger.warning("Failed to send CHECK_UPDATE frame to collector %s: %s", collector_id, e)
            return False


# Global singleton registry for process
collector_registry = CollectorRegistry()
