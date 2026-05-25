from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt
from routers.audit import append_to_audit_log, AuditEntry
from datetime import datetime, timedelta
from jose import jwt

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

# Mock DB for demo purposes
USERS = {
    "sherie@tempris.com": {"password": "demo", "role": "Superadmin", "name": "Sherie"},
    "analyst@tempris.com": {"password": "demo", "role": "Analyst", "name": "Security Analyst"},
    "viewer@tempris.com": {"password": "demo", "role": "Viewer", "name": "Client Viewer"},
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
    if not user or user["password"] != req.password:
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
