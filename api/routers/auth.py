from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import jwt
from passlib.hash import bcrypt
from routers.audit import append_to_audit_log, AuditEntry

import os

router = APIRouter()

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "tempris_dev_only_change_in_prod_" + "x" * 32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

# All 5 user roles per spec — passwords hashed with bcrypt
USERS = {
    "sherie@tempris.com": {"password": bcrypt.hash("demo"), "role": "Superadmin", "name": "Sherie"},
    "admin@tempris.com": {"password": bcrypt.hash("demo"), "role": "Admin", "name": "Platform Admin"},
    "analyst@tempris.com": {"password": bcrypt.hash("demo"), "role": "Analyst", "name": "Security Analyst"},
    "viewer@tempris.com": {"password": bcrypt.hash("demo"), "role": "Viewer", "name": "Client Viewer"},
    "readonly@tempris.com": {"password": bcrypt.hash("demo"), "role": "Read-only", "name": "Audit Reviewer"},
}

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request):
    client_ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    user = USERS.get(req.email)
    if not user or not bcrypt.verify(req.password, user["password"]):
        # Log failed login attempt with IP
        append_to_audit_log(AuditEntry(
            user=req.email,
            action="USER_LOGIN_FAILED",
            module="AUTH",
            detail=f"Failed login attempt for {req.email}",
            ip_address=client_ip
        ))
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
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
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return the user payload.
    
    For the MVP demo, we allow unauthenticated access (returns a default user)
    so the investor demo works without requiring login first.
    In production, this should raise 401 if no valid token is provided.
    """
    if credentials is None:
        # Allow unauthenticated for MVP demo — return default user
        return {"sub": "demo@tempris.com", "role": "Superadmin"}
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def require_role(*allowed_roles):
    """Create a dependency that checks the user's role."""
    def checker(user = Depends(get_current_user)):
        if user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"Insufficient permissions. Required: {', '.join(allowed_roles)}")
        return user
    return checker

