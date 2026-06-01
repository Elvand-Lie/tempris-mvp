from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt
from passlib.hash import bcrypt
from routers.audit import append_to_audit_log, AuditEntry

router = APIRouter()

SECRET_KEY = "tempris_demo_secret_key_do_not_use_in_prod"
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
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    user = USERS.get(req.email)
    if not user or not bcrypt.verify(req.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": req.email, "role": user["role"]}, expires_delta=access_token_expires
    )
    
    append_to_audit_log(AuditEntry(
        user=req.email,
        action="USER_LOGIN",
        module="AUTH",
        detail="User logged in successfully"
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

