from pathlib import Path


NGINX_CONFIG = Path(__file__).resolve().parents[2] / "deploy" / "nginx_ssl.conf"


def test_strict_auth_rate_limit_only_wraps_login():
    config = NGINX_CONFIG.read_text(encoding="utf-8")

    assert "location = /api/auth/login {" in config
    login_block = config.split("location = /api/auth/login {", 1)[1].split("}", 1)[0]
    assert "limit_req zone=auth burst=3 nodelay;" in login_block
    assert "proxy_pass http://127.0.0.1:8000/api/auth/login;" in login_block

    assert "location /api/auth/ {" in config
    auth_block = config.split("location /api/auth/ {", 1)[1].split("}", 1)[0]
    assert "limit_req zone=api burst=20 nodelay;" in auth_block
    assert "limit_req zone=auth" not in auth_block
