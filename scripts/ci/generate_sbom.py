#!/usr/bin/env python3
"""
SDLC-S03: Software Bill of Materials (SBOM) Generator.
Parses requirements.txt and generates a compliant CycloneDX JSON SBOM.
"""
import os
import sys
import json
import uuid
from datetime import datetime, timezone

def parse_requirements(file_path):
    packages = []
    if not os.path.exists(file_path):
        return packages
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Parse package==version or package>=version or package
            parts = line.split("==")
            if len(parts) == 2:
                name = parts[0].strip().lower()
                version = parts[1].strip()
                packages.append((name, version))
            else:
                parts = line.split(">=")
                if len(parts) == 2:
                    name = parts[0].strip().lower()
                    version = parts[1].strip()
                    packages.append((name, version))
    return packages

def generate_cyclonedx_sbom(packages):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Tempris Wave 1 MVP",
                    "name": "Tempris SBOM Generator",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "group": "com.tempris",
                "name": "tempris-backend",
                "version": "1.0.0",
                "type": "application"
            }
        },
        "components": []
    }

    for name, version in packages:
        # Standard Package URL (purl) format for Python packages: pkg:pypi/name@version
        purl = f"pkg:pypi/{name}@{version}"
        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "bom-ref": purl
        }
        sbom["components"].append(component)

    return sbom

def main():
    req_file = os.path.join("app", "backend", "requirements.txt")
    if not os.path.exists(req_file):
        req_file = "requirements.txt"

    print(f"--- SDLC-S03: Generating CycloneDX SBOM from {req_file} ---")
    packages = parse_requirements(req_file)
    
    sbom = generate_cyclonedx_sbom(packages)
    
    # Save output to artifacts/security/sbom/bom.json
    output_dir = os.path.join("artifacts", "security", "sbom")
    os.makedirs(output_dir, exist_ok=True)
    sbom_path = os.path.join(output_dir, "bom.json")
    
    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
        
    print(f"CycloneDX SBOM generated successfully at: {sbom_path}")
    print(f"Total components cataloged: {len(packages)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
