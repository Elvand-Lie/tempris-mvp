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

# All 5 user roles per spec — passwords hashed with bcrypt
USERS = {
    "sherie@tempris.com": {"password": _DEMO_HASH, "role": "Superadmin", "name": "Sherie"},
    "admin@tempris.com": {"password": _DEMO_HASH, "role": "Admin", "name": "Platform Admin"},
    "analyst@tempris.com": {"password": _DEMO_HASH, "role": "Analyst", "name": "Security Analyst"},
    "viewer@tempris.com": {"password": _DEMO_HASH, "role": "Viewer", "name": "Client Viewer"},
    "readonly@tempris.com": {"password": _DEMO_HASH, "role": "Read-only", "name": "Audit Reviewer"},
}

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire, "jti": uuid.uuid4().hex})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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
    return request.cookies.get("tempris_token")

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, response: Response):
    from routers.audit import append_to_audit_log, AuditEntry
    client_ip = request.client.host if request.client else "unknown"

    # Check lockout first
    if _check_lockout(req.email):
        append_to_audit_log(AuditEntry(
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
        # Log failed login attempt with IP
        append_to_audit_log(AuditEntry(
            user=req.email,
            action="USER_LOGIN_FAILED",
            module="AUTH",
            detail=f"Failed login attempt for {req.email}",
            ip_address=client_ip
        ))
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # Successful login — clear any failed attempts
    _clear_attempts(req.email)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": req.email, "role": user["role"]}, expires_delta=access_token_expires
    )
    
    append_to_audit_log(AuditEntry(
        user=req.email,
        action="USER_LOGIN",
        module="AUTH",
        detail="User logged in successfully",
        ip_address=client_ip
    ))
    response.set_cookie(
        "tempris_token",
        access_token,
        httponly=True,
        secure=os.environ.get("ENV", "development").lower() in ("production", "prod"),
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
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
def logout(request: Request, response: Response, db = Depends(get_db)):
    token = _token_from_request(request)
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            payload = {}
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp and not db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
            db.add(RevokedToken(jti=jti, expires_at=datetime.fromtimestamp(exp, timezone.utc)))
            db.commit()
    response.delete_cookie("tempris_token", path="/")
    return {"status": "logged_out"}


from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)

READ_ONLY_ALLOWED_PREFIXES = ("/api/audit", "/api/standard")


def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security), db = Depends(get_db)):
    """Verify JWT token and return the user payload.
    
    L4-04: Requests without valid token are REJECTED (401).
    DEMO_MODE removed — all requests must present a valid JWT.
    """
    token = credentials.credentials if credentials else request.cookies.get("tempris_token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    jti = payload.get("jti")
    if jti and db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        raise HTTPException(status_code=401, detail="Token has been revoked")

    # Check account suspension (anti-distillation enforcement)
    email = payload.get("sub", "")
    try:
        from middleware.tos_enforcer import is_suspended
        if is_suspended(email):
            raise HTTPException(
                status_code=403,
                detail="Account suspended due to Terms of Service violation. Contact support."
            )
    except ImportError:
        pass

    if payload.get("role") == "Read-only" and not request.url.path.startswith(READ_ONLY_ALLOWED_PREFIXES):
        raise HTTPException(
            status_code=403,
            detail="Read-only users can access audit logs and compliance reports only."
        )

    return payload

def require_role(*allowed_roles):
    """Create a dependency that checks the user's role.
    
    H-03: RBAC permission matrix:
    - Superadmin: Full access
    - Admin: All CRUD + approve + reports
    - Analyst: CRUD findings/scenarios, EDIP, scans
    - Viewer: Read-only all modules
    - Read-only: Audit logs + compliance reports only
    """
    def checker(user = Depends(get_current_user)):
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=403, 
                detail=f"Insufficient permissions. Required: {', '.join(allowed_roles)}"
            )
        return user
    return checker
