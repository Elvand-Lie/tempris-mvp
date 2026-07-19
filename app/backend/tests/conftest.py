'''Shared test collection configuration.'''

import os
import sys
import tempfile
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

TEST_ROOT = Path(tempfile.mkdtemp(prefix='tempris-pytest-'))
os.environ['DATABASE_URL'] = 'sqlite:///' + (TEST_ROOT / 'tempris.db').as_posix()
os.environ['EVIDENCE_STORAGE_ROOT'] = str(TEST_ROOT / 'evidence')
os.environ.setdefault('ENVIRONMENT', 'test')
os.environ.setdefault('AUDIT_HMAC_KEY', 'test_audit_hmac_secret_key_12345678')

# Create a clean schema before test modules import global sessions or the app.
from services.database import Base, engine
import models  # noqa: F401

Base.metadata.create_all(bind=engine)
