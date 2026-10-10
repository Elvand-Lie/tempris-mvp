# demo/api/app/main.py — Terra partner demo (WO-10). Replay, not engine:
# this service only loads, serves, resets and audits a checksum-pinned pack.
from __future__ import annotations

import hashlib
import io
import json
import os
import re
from pathlib import Path

import qrcode
import qrcode.image.svg
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import auth, enroll
from .db import PACK_TABLES, init_schema, tenant_conn

PACK_PATH = Path(
    os.environ.get("DEMO_PACK_PATH", Path(__file__).resolve().parent.parent / "pack" / "northwind_freight.v1.json")
)
PACK_SHA256 = os.environ.get("DEMO_PACK_SHA256", "")  # pinned at release

app = FastAPI(title="Tempris Partner Demo", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=os.environ.get("DEMO_ALLOWED_ORIGIN", ".*"),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_pack() -> dict:
    raw = PACK_PATH.read_bytes()
    if PACK_SHA256 and hashlib.sha256(raw).hexdigest() != PACK_SHA256:
        raise RuntimeError("demo pack integrity check failed")
    return json.loads(raw)


def read_pack_pinned() -> dict:
    """Every reset/serve re-verifies the pinned checksum (WO-10 10d)."""
    raw = PACK_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PACK_SHA256:
        raise HTTPException(500, "demo pack integrity check failed")
    return json.loads(raw)


@app.on_event("startup")
def startup() -> None:
    # Schema/role bootstrap requires the ADMIN role. Production deployments
    # run it as a separate one-shot `bootstrap` compose service, so the
    # long-running API process never holds privileged credentials. When
    # ADMIN_DATABASE_URL is set (development, tests), bootstrap inline.
    if os.environ.get("ADMIN_DATABASE_URL"):
        init_schema()
    if not PACK_SHA256:
        raw = PACK_PATH.read_bytes()
        raise RuntimeError(
            "DEMO_PACK_SHA256 must be pinned at release "
            f"(pack sha256 = {hashlib.sha256(raw).hexdigest()})"
        )


class LoginIn(BaseModel):
    username: str
    password: str
    totp_code: str


class StepIn(BaseModel):
    journey: str
    step: int
    title: str | None = None


@app.get("/api/health")
def health():
    return {"ok": True, "service": "tempris-partner-demo"}


@app.post("/demo/login")
def demo_login(payload: LoginIn):
    token = auth.login(payload.username, payload.password, payload.totp_code)
    auth.audit(auth.DEMO_TENANT, payload.username, "demo.login", {})
    return {
        "token": token,
        "user": payload.username,
        "role": "presenter",
        "tenant": auth.DEMO_TENANT,
    }


class RegisterIn(BaseModel):
    username: str
    password: str
    invite_code: str = ""


_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,40}$")


@app.post("/demo/register")
def demo_register(payload: RegisterIn):
    """In-app presenter enrollment with a Tempris-issued invite (WO-10 10c).
    Insert-only: never resets or un-revokes an existing account (see enroll.py).
    Returns the one-time TOTP QR so the presenter can link their authenticator."""
    username = payload.username.strip()
    if not _USERNAME_RE.fullmatch(username):
        raise HTTPException(422, "username must be 3-40 characters: letters, digits, dot, dash, underscore")
    if len(payload.password) < 12:
        raise HTTPException(422, "password must be at least 12 characters")
    try:
        enroll.verify_invite(username, payload.invite_code)
        info = enroll.create_presenter(username, payload.password)
    except HTTPException as exc:
        auth.audit(auth.DEMO_TENANT, username, "demo.register_denied", {"status": exc.status_code})
        raise
    img = qrcode.make(
        info["totp_provisioning_uri"], image_factory=qrcode.image.svg.SvgPathImage
    )
    buf = io.BytesIO()
    img.save(buf)
    auth.audit(auth.DEMO_TENANT, username, "demo.register", {})
    # The provisioning URI/QR is shown exactly once, at enrollment.
    return {"username": username, "qr_svg": buf.getvalue().decode(), "expires_at": info["expires_at"]}


@app.post("/demo/logout")
def demo_logout(request: Request, user=Depends(auth.current_user)):
    token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if token:
        auth.revoke_session(token)
    auth.audit(user["tenant_id"], user["username"], "demo.logout", {})
    return {"status": "logged_out"}


@app.get("/demo/bootstrap")
def bootstrap(user=Depends(auth.current_user)):
    pack = load_pack()
    raw = PACK_PATH.read_bytes()
    return {
        "pack_id": pack["pack_id"],
        "version": pack["version"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "estate": pack["estate"],
        "watermark": "DEMO / SYNTHETIC — NOT A REAL ESTATE",
        "user": user,
    }


@app.get("/demo/pack")
def get_pack(user=Depends(auth.current_user)):
    """Serve the pack from the tenant-scoped tables (RLS in effect)."""
    out: dict = {}
    with tenant_conn(user["tenant_id"]) as conn:
        with conn.cursor() as cur:
            for table, key in PACK_TABLES.items():
                cur.execute(
                    f"SELECT payload FROM {table} ORDER BY ord"
                )
                out[key] = [r[0] for r in cur.fetchall()]
            for blob_key in ("journeys", "report", "estate"):
                cur.execute(
                    "SELECT payload FROM pack_blobs WHERE tenant_id = %s AND key = %s",
                    (user["tenant_id"], blob_key),
                )
                row = cur.fetchone()
                out[blob_key] = row[0] if row else ({} if blob_key != "estate" else None)
    if not out.get("assets"):
        raise HTTPException(409, "demo pack not loaded — reset the demo first")
    if not out.get("assets"):
        raise HTTPException(409, "demo pack not loaded — reset the demo first")
    return out


@app.post("/demo/reset")
def reset(user=Depends(auth.current_user)):
    """One-click baseline restore: verify checksum, wipe tenant rows, reload.
    Deterministic; well under the 60s budget for a pack this size."""
    pack = read_pack_pinned()
    with tenant_conn(user["tenant_id"]) as conn:
        with conn.cursor() as cur:
            for table in PACK_TABLES:
                cur.execute(f"DELETE FROM {table}")
            cur.execute("DELETE FROM pack_blobs WHERE tenant_id = %s", (user["tenant_id"],))
            for table, key in PACK_TABLES.items():
                for ord_, item in enumerate(pack.get(key, [])):
                    cur.execute(
                        f"INSERT INTO {table} (tenant_id, ord, payload) VALUES (%s, %s, %s)",
                        (user["tenant_id"], ord_, json.dumps(item)),
                    )
            for key in ("journeys", "report", "estate"):
                cur.execute(
                    "INSERT INTO pack_blobs (tenant_id, key, payload) VALUES (%s, %s, %s)",
                    (user["tenant_id"], key, json.dumps(pack.get(key, {}))),
                )
    auth.audit(user["tenant_id"], user["username"], "demo.reset", {"pack": PACK_PATH.name})
    return {"status": "reset", "pack": PACK_PATH.name}


@app.post("/demo/journey-event")
def journey_event(payload: StepIn, user=Depends(auth.current_user)):
    """Audit one navigation event. Journey/step are validated against the
    pinned pack so fabricated events cannot be recorded as journey evidence;
    free-form EXPLORE navigation stays allowed within sane bounds."""
    if payload.journey == "EXPLORE":
        if not (1 <= payload.step <= 12):
            raise HTTPException(422, "invalid explore step")
    else:
        journeys = load_pack().get("journeys", {})
        steps = journeys.get(payload.journey, {}).get("steps", [])
        if not any(s.get("n") == payload.step for s in steps):
            raise HTTPException(
                422, f"unknown journey step: {payload.journey} / {payload.step}"
            )
    auth.audit(
        user["tenant_id"], user["username"], "demo.journey_step",
        {"journey": payload.journey, "step": payload.step, "title": payload.title},
    )
    return {"status": "recorded"}


class ExportIn(BaseModel):
    kind: str = "report.pdf"


@app.post("/demo/export")
def export_event(payload: ExportIn, user=Depends(auth.current_user)):
    """Audit that the presenter initiated a watermarked report print/export
    (WO-10 10c / acceptance g). The PDF is rendered by the presenter's browser
    from the already-served pack; this records the initiated action, not a
    confirmed file save."""
    auth.audit(user["tenant_id"], user["username"], "demo.export", {"kind": payload.kind[:60], "pack": PACK_PATH.name})
    return {"status": "recorded"}


@app.get("/demo/audit")
def audit_log(user=Depends(auth.current_user)):
    with tenant_conn(user["tenant_id"]) as conn:
        with conn.cursor() as conn_cur:
            conn_cur.execute(
                "SELECT event, detail, at FROM audit_events ORDER BY at DESC LIMIT 200"
            )
            rows = [
                {"event": e, "detail": d, "at": a.isoformat()}
                for e, d, a in conn_cur.fetchall()
            ]
    return {"events": rows}
