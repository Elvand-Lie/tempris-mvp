import pytest
import os
import sys
from fastapi.testclient import TestClient
from passlib.hash import bcrypt
from services.database import get_db
from index import app

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

@pytest.fixture(autouse=True)
def bypass_rate_limiter(monkeypatch):
    from middleware.rate_limit import _Bucket
    monkeypatch.setattr(_Bucket, "consume", lambda self: True)

def test_aev_endpoints_are_disabled():
    from routers.auth import USERS
    USERS["admin_aev@tempris.com"] = {
        "password": bcrypt.hash("pwd_aev"),
        "role": "Admin",
        "name": "AEV Admin",
        "tenant_id": "tenantA"
    }

    client = TestClient(app)
    
    # Login
    resp_login = client.post("/api/auth/login", json={"email": "admin_aev@tempris.com", "password": "pwd_aev"})
    assert resp_login.status_code == 200
    headers = {"Authorization": f"Bearer {resp_login.json()['access_token']}"}

    # 1. POST /api/aev/runs must be disabled
    resp_create = client.post("/api/aev/runs", json={"module_id": "ATLAS", "target_input": {}}, headers=headers)
    assert resp_create.status_code == 400
    assert "AEV_DISABLED" in resp_create.json()["detail"]

    # 2. POST /api/aev/runs/RUN-1/authorize must be disabled
    resp_auth = client.post("/api/aev/runs/RUN-1/authorize", headers=headers)
    assert resp_auth.status_code == 400
    assert "AEV_DISABLED" in resp_auth.json()["detail"]

    # 3. POST /api/aev/runs/RUN-1/execute must be disabled
    resp_exec = client.post("/api/aev/runs/RUN-1/execute", headers=headers)
    assert resp_exec.status_code == 400
    assert "AEV_DISABLED" in resp_exec.json()["detail"]

    # 4. POST /api/aev/runs/RUN-1/pause must be disabled
    resp_pause = client.post("/api/aev/runs/RUN-1/pause", headers=headers)
    assert resp_pause.status_code == 400
    assert "AEV_DISABLED" in resp_pause.json()["detail"]
