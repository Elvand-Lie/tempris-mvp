#!/usr/bin/env python3
'''Generate a CycloneDX JSON SBOM for backend and FreeLLMAPI dependencies.'''

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


BACKEND_REQUIREMENTS = Path('app/backend/requirements.txt')
FREELLMAPI_LOCKFILE = Path('app/freellmapi/package-lock.json')
OUTPUT_PATH = Path('artifacts/security/sbom/bom.json')


def parse_requirements(file_path: Path) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    if not file_path.is_file():
        return packages
    for raw_line in file_path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if '==' in line:
            name, version = line.split('==', 1)
        elif '>=' in line:
            name, version = line.split('>=', 1)
        else:
            continue
        packages.append((name.strip().lower(), version.strip()))
    return packages


def parse_npm_lockfile(file_path: Path) -> list[tuple[str, str]]:
    if not file_path.is_file():
        return []
    lockfile = json.loads(file_path.read_text(encoding='utf-8'))
    packages: list[tuple[str, str]] = []
    for package_path, details in lockfile.get('packages', {}).items():
        if not package_path or not package_path.startswith('node_modules/'):
            continue
        name = details.get('name') or package_path.rsplit('node_modules/', 1)[1]
        version = details.get('version')
        if isinstance(name, str) and isinstance(version, str):
            packages.append((name, version))
    return packages


def component(name: str, version: str, ecosystem: str) -> dict:
    encoded_name = quote(name, safe='/')
    encoded_version = quote(version, safe='')
    purl = f'pkg:{ecosystem}/{encoded_name}@{encoded_version}'
    return {
        'type': 'library',
        'name': name,
        'version': version,
        'purl': purl,
        'bom-ref': purl,
    }


def generate_cyclonedx_sbom(
    python_packages: list[tuple[str, str]],
    node_packages: list[tuple[str, str]],
) -> dict:
    components = []
    seen: set[tuple[str, str, str]] = set()
    for ecosystem, packages in (('pypi', python_packages), ('npm', node_packages)):
        for name, version in packages:
            key = (ecosystem, name, version)
            if key not in seen:
                seen.add(key)
                components.append(component(name, version, ecosystem))
    components.sort(key=lambda item: (item['purl'], item['name'], item['version']))
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'version': 1,
        'metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tools': [
                {
                    'vendor': 'Tempris',
                    'name': 'Tempris SBOM Generator',
                    'version': '1.1.0',
                }
            ],
            'component': {
                'group': 'com.tempris',
                'name': 'tempris-platform',
                'version': '1.0.0',
                'type': 'application',
            },
        },
        'components': components,
    }


def main() -> int:
    python_packages = parse_requirements(BACKEND_REQUIREMENTS)
    node_packages = parse_npm_lockfile(FREELLMAPI_LOCKFILE)
    sbom = generate_cyclonedx_sbom(python_packages, node_packages)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(sbom, indent=2) + '\n', encoding='utf-8')
    print('CycloneDX SBOM generated at ' + str(OUTPUT_PATH))
    print('Python components: ' + str(len(python_packages)))
    print('Node components: ' + str(len(node_packages)))
    print('Total components: ' + str(len(sbom['components'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
