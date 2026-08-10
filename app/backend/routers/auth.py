from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import jwt
from passlib.hash import bcrypt
# NOTE: audit imports (append_to_audit_log, AuditEntry) are done lazily
# inside function bodies to avoid circular import with audit.py
import os
import sys
import uuid
from services.database import get_db
from models import RevokedToken
from sqlalchemy.orm import Session

router = APIRouter()

# ── H-01: JWT Secret — fail-closed if not set in production ───────────────────
_fallback_secret = "tempris_dev_only_change_in_prod_" + "x" * 32
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")

if not SECRET_KEY:
    if os.environ.get("ENV", "development").lower() in ("production", "prod"):
        print("FATAL: JWT_SECRET_KEY is not set in production. Refusing to start.", file=sys.stderr)
        sys.exit(1)
    else:
        SECRET_KEY = _fallback_secret
        print("WARNING: Using development JWT secret. Set JWT_SECRET_KEY for production.", file=sys.stderr)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # H-02: Reduced from 120 to 60

# ── Brute-force lockout tracking ──────────────────────────────────────────────
# M-05: In-memory tracker resets on container restart. For production scale,
# consider moving to Redis or DB-backed lockout tracking.
# {email: {"attempts": int, "locked_until": datetime | None}}
_login_attempts: dict[str, dict] = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

# Pre-compute bcrypt hash once to avoid re-hashing on every startup
_DEMO_HASH = bcrypt.hash("demo")

def _init_users() -> dict:
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    ALLOWED_ENVIRONMENTS = {"demo", "test", "development", "staging", "production"}
    if not env:
        raise RuntimeError("FATAL: ENVIRONMENT configuration variable is missing or empty.")
    if env not in ALLOWED_ENVIRONMENTS:
        raise RuntimeError(f"FATAL: Unrecognized ENVIRONMENT value: '{env}'")

    is_demo = (env == "demo")
    is_test = (env == "test")

    pass_superadmin = os.environ.get("TEMPRIS_PASS_SUPERADMIN")
    pass_admin = os.environ.get("TEMPRIS_PASS_ADMIN")
    pass_analyst = os.environ.get("TEMPRIS_PASS_ANALYST")
    pass_viewer = os.environ.get("TEMPRIS_PASS_VIEWER")
    pass_readonly = os.environ.get("TEMPRIS_PASS_READONLY")
    pass_researcher = os.environ.get("TEMPRIS_PASS_RESEARCHER")

    # For non-demo/non-test environments, or test environment with some credentials set, require all credentials
    if not is_demo and not (is_test and not any([pass_superadmin, pass_admin, pass_analyst, pass_viewer, pass_readonly, pass_researcher])):
        missing = []
        for name, val in [
            ("TEMPRIS_PASS_SUPERADMIN", pass_superadmin),
            ("TEMPRIS_PASS_ADMIN", pass_admin),
            ("TEMPRIS_PASS_ANALYST", pass_analyst),
            ("TEMPRIS_PASS_VIEWER", pass_viewer),
            ("TEMPRIS_PASS_READONLY", pass_readonly),
            ("TEMPRIS_PASS_RESEARCHER", pass_researcher)
        ]:
            if not val:
                missing.append(name)
            elif val == "demo":
                raise RuntimeError(f"FATAL: Password for {name} cannot be 'demo' outside ENVIRONMENT=demo")
        if missing:
            raise RuntimeError("FATAL: Missing unique credentials for non-demo environment.")

        if env in ("staging", "production"):
            passwords = [pass_superadmin, pass_admin, pass_analyst, pass_viewer, pass_readonly, pass_researcher]
            if len(passwords) != len(set(passwords)):
                raise RuntimeError("FATAL: Shared/duplicated passwords are not permitted across privileged accounts in staging or production.")

    hash_superadmin = bcrypt.hash(pass_superadmin) if pass_superadmin else _DEMO_HASH
    hash_admin = bcrypt.hash(pass_admin) if pass_admin else _DEMO_HASH
    hash_analyst = bcrypt.hash(pass_analyst) if pass_analyst else _DEMO_HASH
    hash_viewer = bcrypt.hash(pass_viewer) if pass_viewer else _DEMO_HASH
    hash_readonly = bcrypt.hash(pass_readonly) if pass_readonly else _DEMO_HASH
    hash_researcher = bcrypt.hash(pass_researcher) if pass_researcher else _DEMO_HASH

    # NOTE: The USERS dictionary mapping is a temporary compatibility implementation for Wave 1 MVP auth.
    return {
        "sherie@tempris.com": {"password": hash_superadmin, "role": "Superadmin", "name": "Sherie", "tenant_id": "tempris"},
        "admin@tempris.com": {"password": hash_admin, "role": "Admin", "name": "Platform Admin", "tenant_id": "tempris"},
        "analyst@tempris.com": {"password": hash_analyst, "role": "Analyst", "name": "Security Analyst", "tenant_id": "tempris"},
        "viewer@tempris.com": {"password": hash_viewer, "role": "Viewer", "name": "Client Viewer", "tenant_id": "tempris"},
        "readonly@tempris.com": {"password": hash_readonly, "role": "Read-only", "name": "Audit Reviewer", "tenant_id": "tempris"},
        "researcher@tempris.com": {"password": hash_researcher, "role": "Researcher", "name": "Security Researcher", "tenant_id": "bug-bounty"},
    }

USERS = _init_users()



def create_access_token(data: dict, expires_delta: timedelta | None = None):
    sub = data.get("sub")
    sid = data.get("sid")
    jti = data.get("jti") or uuid.uuid4().hex
    if not sub or not sid:
        raise ValueError("sub and sid are required to generate access token")

    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {
        "sub": sub,
        "sid": sid,
        "jti": jti,
        "iat": now,
        "exp": expire,
        "token_version": "v2"
    }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_test_session(db, email: str, expires_delta: timedelta | None = None) -> str:
    """Helper for testing to create a genuine persisted session and return the JWT token."""
    import uuid
    import hashlib
    from models import UserSession
    
    sid = str(uuid.uuid4())
    jti = uuid.uuid4().hex
    jti_hash = hashlib.sha256(jti.encode()).hexdigest()
    
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
    session = UserSession(
        id=sid,
        account_subject=email,
        jti_hash=jti_hash,
        issued_at=now,
        expires_at=expire,
        created_at=now
    )
    db.add(session)
    db.commit()
    
    token = create_access_token(data={"sub": email, "sid": sid, "jti": jti}, expires_delta=expires_delta)
    return token

def _check_lockout(email: str) -> bool:
    """Returns True if account is currently locked out."""
    record = _login_attempts.get(email)
    if not record:
        return False
    locked_until = record.get("locked_until")
    if locked_until and datetime.now(timezone.utc) < locked_until:
        return True
    # Lockout expired — reset
    if locked_until and datetime.now(timezone.utc) >= locked_until:
        _login_attempts.pop(email, None)
    return False

def _record_failed_attempt(email: str):
    """Track failed login attempt. Lock account after MAX_LOGIN_ATTEMPTS."""
    record = _login_attempts.setdefault(email, {"attempts": 0, "locked_until": None})
    record["attempts"] += 1
    if record["attempts"] >= MAX_LOGIN_ATTEMPTS:
        record["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)

def _clear_attempts(email: str):
    """Clear failed attempt counter on successful login."""
    _login_attempts.pop(email, None)


def _token_from_request(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    from routers.audit import append_to_audit_log_db, AuditEntry
    from models import UserSession
    import hashlib

    client_ip = request.client.host if request.client else "unknown"

    # Check lockout first
    if _check_lockout(req.email):
        append_to_audit_log_db(db, AuditEntry(
            user=req.email,
            action="USER_LOGIN_LOCKED",
            module="AUTH",
            detail=f"Login attempt rejected — account locked after {MAX_LOGIN_ATTEMPTS} failed attempts",
            ip_address=client_ip
        ))
        raise HTTPException(
            status_code=429,
            detail=f"Account temporarily locked after {MAX_LOGIN_ATTEMPTS} failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes."
        )

    user = USERS.get(req.email)
    if not user or not bcrypt.verify(req.password, user["password"]):
        _record_failed_attempt(req.email)
        append_to_audit_log_db(db, AuditEntry(
            user=req.email,
            action="USER_LOGIN_FAILED",
            module="AUTH",
            detail=f"Failed login attempt for {req.email}",
            ip_address=client_ip
        ))
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # Successful login — clear any failed attempts
    _clear_attempts(req.email)

    if user.get("disabled") is True:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Password verification establishes the server-side principal for the
    # transactional login audit; no actor or tenant comes from request data.
    request.state.authenticated_user = {
        "sub": req.email,
        "tenant_id": user.get("tenant_id"),
        "role": user.get("role"),
    }

    # Generate session parameters
    sid = str(uuid.uuid4())
    jti = uuid.uuid4().hex
    jti_hash = hashlib.sha256(jti.encode()).hexdigest()

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_agent = request.headers.get("user-agent", "")[:255]

    try:
        session_record = UserSession(
            id=sid,
            account_subject=req.email,
            jti_hash=jti_hash,
            issued_at=now,
            expires_at=expires_at,
            created_at=now,
            user_agent=user_agent
        )
        db.add(session_record)
        db.flush()

        # Audit successful login inside the same transaction
        append_to_audit_log_db(db, AuditEntry(
            user=req.email,
            action="USER_LOGIN",
            module="AUTH",
            detail=f"User logged in successfully. Session created: {sid}",
            ip_address=client_ip
        ), commit=False)

        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database failure during login session persistence")

    # Create signed token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": req.email,
            "sid": sid,
            "jti": jti
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": {
            "email": req.email,
            "name": user["name"],
            "role": user["role"]
        }
    }

# ── JWT Auth Guard ─────────────────────────────────────────────────────────
@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = _token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    # 1. Validate JWT signature, algorithm and claims strictly
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication required")

    email = payload.get("sub")
    sid = payload.get("sid")
    jti = payload.get("jti")
    iat = payload.get("iat")
    exp = payload.get("exp")
    token_version = payload.get("token_version")

    # Ensure all claims are present and correct version
    if not all([email, sid, jti, iat, exp]) or token_version != "v2":
        raise HTTPException(status_code=401, detail="Authentication required")

    # 2. Resolve the exact persisted session and verify subject/JTI hash correspondence
    from models import UserSession
    from routers.audit import append_to_audit_log_db, AuditEntry
    import hashlib

    try:
        session = db.query(UserSession).filter(UserSession.id == sid).first()
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication required")

    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")

    if session.account_subject != email:
        raise HTTPException(status_code=401, detail="Authentication required")

    expected_hash = hashlib.sha256(jti.encode()).hexdigest()
    if session.jti_hash != expected_hash:
        raise HTTPException(status_code=401, detail="Authentication required")

    # 3. Handle already-revoked session (idempotency: return 200 OK without making any db updates or audits)
    if session.revoked_at is not None:
        response.delete_cookie("tempris_token", path="/")
        return {"status": "logged_out"}

    # 4. Perform revocation inside transaction
    try:
        session.revoked_at = datetime.now(timezone.utc)
        session.revoking_actor = email
        session.revocation_reason = "User logout"
        db.flush()
        
        append_to_audit_log_db(db, AuditEntry(
            user=email,
            action="USER_LOGOUT",
            module="AUTH",
            detail=f"User logged out successfully. Session revoked: {sid}"
        ), commit=False)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database failure during logout session revocation")

    response.delete_cookie("tempris_token", path="/")
    return {"status": "logged_out"}


from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)

READ_ONLY_ALLOWED_PREFIXES = ("/api/audit", "/api/standard")
RESEARCHER_ALLOWED_ROUTES = frozenset({
    ("GET", "/api/packages/current"),
    ("GET", "/api/edip/intake/sss"),
    ("GET", "/api/edip/intake/sss/events"),
    ("POST", "/api/edip/intake/sss"),
    ("POST", "/api/auth/logout"),
})


def _normalize_datetime(dt) -> datetime | None:
    if not dt:
        return None
    if isinstance(dt, str):
        try:
            if "." in dt:
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            else:
                dt = datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security), db = Depends(get_db)):
    """Verify JWT token, validate matching server-side session, and return user payload."""
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    email = payload.get("sub")
    sid = payload.get("sid")
    jti = payload.get("jti")
    iat = payload.get("iat")
    exp = payload.get("exp")
    token_version = payload.get("token_version")

    # Reject tokens without required claims or non-v2 token version
    if not all([email, sid, jti, iat, exp]) or token_version != "v2":
        raise HTTPException(status_code=401, detail="Authentication required")

    # Check account suspension (anti-distillation enforcement)
    try:
        from middleware.tos_enforcer import is_suspended
        if is_suspended(email):
            raise HTTPException(
                status_code=403,
                detail="Account suspended due to Terms of Service violation. Contact support."
            )
    except ImportError:
        pass

    # Verify user against configuration-backed account registry (USERS)
    user_record = USERS.get(email)
    if not user_record:
        raise HTTPException(status_code=401, detail="User account not found")

    if user_record.get("disabled") is True:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Verify matching server-side session
    from models import UserSession
    import hashlib
    try:
        session = db.query(UserSession).filter(UserSession.id == sid).first()
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication required")

    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")

    if session.account_subject != email:
        raise HTTPException(status_code=401, detail="Authentication required")

    expected_hash = hashlib.sha256(jti.encode()).hexdigest()
    if session.jti_hash != expected_hash:
        raise HTTPException(status_code=401, detail="Authentication required")

    if session.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Authentication required")

    now = datetime.now(timezone.utc)
    
    expires_at = _normalize_datetime(session.expires_at)
    if expires_at and expires_at < now:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Throttle last-seen updates (5 minute interval)
    last_seen = _normalize_datetime(session.last_seen_at)
    if not last_seen or (now - last_seen).total_seconds() > 300:
        from services.database import SessionLocal
        import logging
        update_db = SessionLocal()
        try:
            db_session = update_db.query(UserSession).filter(UserSession.id == sid).first()
            if db_session:
                db_session.last_seen_at = now
                update_db.commit()
        except Exception as e:
            update_db.rollback()
            logging.warning("Failed to update last_seen_at for session ID: %s. Error: %s", sid, str(e))
        finally:
            update_db.close()

    record_role = user_record.get("role")
    record_tenant = user_record.get("tenant_id")

    server_payload = {
        "sub": email,
        "role": record_role,
        "tenant_id": record_tenant
    }

    if record_role == "Read-only" and not request.url.path.startswith(READ_ONLY_ALLOWED_PREFIXES):
        raise HTTPException(
            status_code=403,
            detail="Read-only users can access audit logs and compliance reports only."
        )

    if record_role == "Researcher" and (request.method.upper(), request.url.path) not in RESEARCHER_ALLOWED_ROUTES:
        raise HTTPException(
            status_code=403,
            detail="Researcher users can create and view isolated SSS test findings only."
        )

    # Propagate the authenticated user to request state
    request.state.authenticated_user = server_payload

    return server_payload


@router.get("/sessions")
def list_sessions(
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    """List active and history sessions belonging to the caller subject."""
    from models import UserSession
    from routers.auth import get_auth_context
    
    auth_ctx = get_auth_context(user)
    caller_sub = auth_ctx.user_id
    
    current_sid = None
    token = _token_from_request(request)
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
            current_sid = payload.get("sid")
        except Exception:
            pass

    sessions = db.query(UserSession).filter(UserSession.account_subject == caller_sub).all()
    
    res = []
    now = datetime.now(timezone.utc)
    for s in sessions:
        issued_dt = _normalize_datetime(s.issued_at)
        expires_dt = _normalize_datetime(s.expires_at)
        last_seen_dt = _normalize_datetime(s.last_seen_at)
        revoked_dt = _normalize_datetime(s.revoked_at)

        if revoked_dt is not None:
            status = "revoked"
        elif expires_dt and expires_dt < now:
            status = "expired"
        else:
            status = "active"
            
        ua_label = s.user_agent[:50] if s.user_agent else "Unknown"
        
        res.append({
            "session_id": s.id,
            "issued_at": issued_dt.isoformat() if issued_dt else None,
            "expires_at": expires_dt.isoformat() if expires_dt else None,
            "last_seen_at": last_seen_dt.isoformat() if last_seen_dt else None,
            "revoked_at": revoked_dt.isoformat() if revoked_dt else None,
            "user_agent": ua_label,
            "status": status,
            "is_current": (s.id == current_sid)
        })
    return {"sessions": res}


@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):
    """Revokes a session by session_id. Enforces role/tenant authorization."""
    from models import UserSession
    from routers.auth import get_auth_context, USERS
    from routers.audit import append_to_audit_log_db, AuditEntry
    
    auth_ctx = get_auth_context(user)
    caller_sub = auth_ctx.user_id
    caller_role = auth_ctx.role
    caller_tenant = auth_ctx.tenant_id

    session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    target_sub = session.account_subject
    target_user = USERS.get(target_sub)
    target_tenant = target_user.get("tenant_id") if target_user else None

    # Enforce revocation permissions
    authorized = False
    audit_action = None

    if target_sub == caller_sub:
        authorized = True
        audit_action = "SESSION_REVOKED_BY_OWNER"
    elif auth_ctx.is_superadmin:
        authorized = True
        audit_action = "SESSION_REVOKED_BY_SUPERADMIN"
    elif caller_role == "Admin":
        if target_tenant == caller_tenant:
            authorized = True
            audit_action = "SESSION_REVOKED_BY_ADMIN"
            
    if not authorized:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.revoked_at is not None:
        return {"status": "success", "message": "Session has been revoked"}

    try:
        session.revoked_at = datetime.now(timezone.utc)
        session.revoking_actor = caller_sub
        session.revocation_reason = "Administrative action" if target_sub != caller_sub else "User action"
        db.flush()
        
        append_to_audit_log_db(db, AuditEntry(
            user=caller_sub,
            action=audit_action,
            module="AUTH",
            detail=f"Session {session_id} for user {target_sub} revoked by {caller_sub} ({caller_role})"
        ), commit=False)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database failure during session revocation")

    return {"status": "success", "message": "Session has been revoked"}


def require_role(*allowed_roles):
    """Create a dependency that checks the user's role.
    
    H-03: RBAC permission matrix:
    - Superadmin: Full access
    - Admin: All CRUD + approve + reports
    - Analyst: CRUD findings/scenarios, EDIP, scans
    - Viewer: Read-only all modules
    - Read-only: Audit logs + compliance reports only
    - Researcher: Create and view SSS test findings in an isolated tenant only
    """
    async def checker(user = Depends(get_current_user)):
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=403, 
                detail=f"Insufficient permissions. Required: {', '.join(allowed_roles)}"
            )
        return user
    return checker


PLATFORM_TENANT_ID = os.environ.get("TEMPRIS_PLATFORM_TENANT_ID", "tempris").strip() or "tempris"


def require_platform_superadmin():
    """Require the configured platform tenant as well as the Superadmin role.

    A Superadmin belonging to a customer tenant remains powerful inside that
    tenant but cannot enumerate or modify other tenants.
    """
    async def checker(user=Depends(get_current_user)):
        if user.get("role") != "Superadmin" or user.get("tenant_id") != PLATFORM_TENANT_ID:
            raise HTTPException(
                status_code=403,
                detail="Platform Superadmin access is required.",
            )
        return user
    return checker


# ── Centralized Authorization Abstractions ──────────────────────────────────
from dataclasses import dataclass
from enum import Enum
from typing import Set, Optional
from sqlalchemy.orm import Session
from models import ControlEvidence

class EvidencePermission(str, Enum):
    LIST = "list"
    READ = "read"
    PREVIEW = "preview"
    DOWNLOAD = "download"
    DELETE = "delete"

@dataclass(frozen=True)
class AuthContext:
    user_id: str
    tenant_id: str
    role: str
    permissions: frozenset[str]
    is_superadmin: bool

ROLE_PERMISSIONS = {
    "Superadmin": frozenset({"list", "read", "preview", "download", "delete"}),
    "Admin": frozenset({"list", "read", "preview", "download", "delete"}),
    "Analyst": frozenset({"list", "read", "preview", "download"}),
    "Viewer": frozenset({"list", "read"}),
    "Read-only": frozenset({"list"}),
    "Researcher": frozenset(),
    "partner-admin": frozenset({"list", "read", "preview", "download", "delete"}),
    "partner-analyst": frozenset({"list", "read", "preview", "download"}),
}

EVIDENCE_CONTENT_ROLES = frozenset({
    "Superadmin", "Admin", "Analyst", "partner-admin", "partner-analyst",
})

def get_auth_context(user_payload: dict) -> AuthContext:
    email = user_payload.get("sub", "")
    role = user_payload.get("role", "Read-only")
    tenant_id = user_payload.get("tenant_id")
    is_superadmin = (role == "Superadmin")
    permissions = ROLE_PERMISSIONS.get(role, frozenset())
    return AuthContext(
        user_id=email,
        tenant_id=tenant_id,
        role=role,
        permissions=permissions,
        is_superadmin=is_superadmin
    )

def scoped_evidence_query(
    db: Session,
    *,
    user: AuthContext,
    evidence_id: Optional[int] = None,
    framework_id: Optional[str] = None,
    control_id: Optional[str] = None,
    required_permission: EvidencePermission,
) -> Session:
    # 1. Enforce Action Permission
    if required_permission.value not in user.permissions:
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions for action: {required_permission.value}"
        )

    # 2. Prevent role bypasses (Viewer/Analyst cannot delete)
    if required_permission == EvidencePermission.DELETE and user.role not in ("Superadmin", "Admin", "partner-admin"):
        raise HTTPException(status_code=403, detail="Permission denied")

    # 3. Evidence contents require Analyst+ for every compliance framework.
    if required_permission in (EvidencePermission.DOWNLOAD, EvidencePermission.PREVIEW):
        if user.role not in EVIDENCE_CONTENT_ROLES:
            raise HTTPException(status_code=403, detail="Permission denied")

    # 4. Build Scoped Query
    query = db.query(ControlEvidence)

    if evidence_id is not None:
        query = query.filter(ControlEvidence.id == evidence_id)
    if framework_id is not None:
        query = query.filter(ControlEvidence.framework_id == framework_id)
    if control_id is not None:
        query = query.filter(ControlEvidence.control_id == control_id)

    # 5. Enforce Tenant Scoping (Superadmin bypasses)
    if not user.is_superadmin:
        query = query.filter(ControlEvidence.tenant_id == user.tenant_id)

    return query

