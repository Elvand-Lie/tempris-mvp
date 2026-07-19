#!/usr/bin/env python3
'''Generate and verify an HMAC-protected Tempris provenance manifest.

This is shared-secret integrity verification. It is not identity-backed
digital signing and must only run with an injected CI or release secret.
'''

import argparse
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_MANIFEST = Path('artifacts/security/provenance/provenance.json')
FILES_TO_HASH = (
    Path('app/backend/requirements.txt'),
    Path('app/backend/models.py'),
    Path('app/backend/index.py'),
    Path('app/freellmapi/package-lock.json'),
    Path('app/freellmapi/src/db/index.ts'),
    Path('artifacts/security/sbom/bom.json'),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument('--verify-only', action='store_true')
    return parser.parse_args()


def signing_key() -> bytes:
    value = os.environ.get('PROVENANCE_SIGNING_KEY')
    if not value:
        raise RuntimeError('PROVENANCE_SIGNING_KEY is required')
    return value.encode('utf-8')


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(8192), b''):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_manifest(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')


def build_manifest() -> dict:
    missing = [str(path) for path in FILES_TO_HASH if not path.is_file()]
    if missing:
        raise RuntimeError('Required provenance input is missing: ' + ', '.join(missing))
    return {
        'build_tool': 'Tempris HMAC provenance manifest',
        'provenance_method': 'HMAC-SHA256 shared-secret integrity verification',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'artifacts': {
            path.as_posix(): hash_file(path)
            for path in FILES_TO_HASH
        },
    }


def build_bundle(key: bytes) -> dict:
    manifest = build_manifest()
    return {
        'manifest': manifest,
        'signature': hmac.new(key, canonical_manifest(manifest), hashlib.sha256).hexdigest(),
        'signing_algorithm': 'HMAC-SHA256',
    }


def verify_bundle(bundle: dict, key: bytes) -> tuple[bool, str]:
    manifest = bundle.get('manifest')
    signature = bundle.get('signature')
    if not isinstance(manifest, dict) or not isinstance(signature, str):
        return False, 'Manifest is malformed'
    expected = hmac.new(key, canonical_manifest(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False, 'HMAC verification failed'
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, dict):
        return False, 'Artifact list is malformed'
    for raw_path, expected_hash in artifacts.items():
        artifact = Path(raw_path)
        if not artifact.is_file() or hash_file(artifact) != expected_hash:
            return False, 'Artifact hash verification failed for ' + raw_path
    return True, 'HMAC and artifact hashes verified'


def main() -> int:
    args = parse_args()
    try:
        key = signing_key()
        if args.verify_only:
            bundle = json.loads(args.manifest.read_text(encoding='utf-8'))
            verified, message = verify_bundle(bundle, key)
            print(message)
            return 0 if verified else 1

        bundle = build_bundle(key)
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(bundle, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        verified, message = verify_bundle(bundle, key)
        print('Provenance manifest generated at ' + str(args.manifest))
        print(message)
        return 0 if verified else 1
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print('Provenance verification failed: ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
