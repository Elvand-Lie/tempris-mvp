# backend/app/collector_registry.py
import asyncio
import collections
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple
from fastapi import WebSocket
from app.db import get_db_connection
from app.audit import record_audit_event

logger = logging.getLogger("collector_registry")

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
        self.in_flight_jobs: Dict[str, asyncio.Future] = {}
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
                future.set_result({
                    "job_id": job_id,
                    "status": "failed",
                    "reachability_status": "unverified",
                    "error_message": error_message
                })
        self.in_flight_jobs.clear()


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
            future.set_result(result_payload)
            return True
        return False


# Global singleton registry for process
collector_registry = CollectorRegistry()
