#!/usr/bin/env python3
#  SDLC-S04: MVP shared-secret provenance authentication.
# Calculates SHA-256 hashes of build files, signs the manifest, and provides verification.
import os
import sys
import json
import hashlib
import hmac
from datetime import datetime, timezone

# Simple HMAC secret used for local build signing. In real CI, this is loaded from secret environment variables.
PROVENANCE_KEY = os.environ.get("PROVENANCE_SIGNING_KEY", "local_development_provenance_secret_key_123").encode("utf-8")

def hash_file(file_path):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            while chunk:
                h.update(chunk)
                chunk = f.read(8192)
        return h.hexdigest()
    except Exception:
        return None

def main():
    print("--- SDLC-S04: Generating MVP Shared-Secret Provenance Authentication Manifest ---")
    
    # Files to include in build provenance
    files_to_hash = [
        os.path.join("app", "backend", "requirements.txt"),
        os.path.join("app", "backend", "models.py"),
        os.path.join("app", "backend", "index.py"),
        os.path.join("artifacts", "security", "sbom", "bom.json")
    ]
    
    timestamp_str = datetime.now(timezone.utc).isoformat()
    manifest = {
        "build_tool": "Tempris Secure Software Factory (MVP Shared-Secret Authentication)",
        "timestamp": timestamp_str,
        "artifacts": {}
    }
    
    # Calculate checksums
    for f_path in files_to_hash:
        if os.path.exists(f_path):
            f_hash = hash_file(f_path)
            if f_hash:
                # Normalize path for compatibility
                norm_path = f_path.replace("\\", "/")
                manifest["artifacts"][norm_path] = f_hash
                
    # Generate signature using HMAC-SHA256
    serialized = json.dumps(manifest, sort_keys=True)
    signature = hmac.new(PROVENANCE_KEY, serialized.encode("utf-8"), hashlib.sha256).hexdigest()
    
    provenance_bundle = {
        "manifest": manifest,
        "signature": signature,
        "signing_algorithm": "HMAC-SHA256"
    }
    
    # Save provenance file
    output_path = os.path.join("artifacts", "security", "provenance", "provenance.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(provenance_bundle, f, indent=2)
        
    print(f"Build provenance authentication manifest generated successfully at: {output_path}")
    
    # Verify the signature immediately to validate build verification logic
    print("\nVerifying build provenance authentication authenticity...")
    with open(output_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        
    loaded_manifest = loaded["manifest"]
    loaded_sig = loaded["signature"]
    
    serialized_loaded = json.dumps(loaded_manifest, sort_keys=True)
    computed_sig = hmac.new(PROVENANCE_KEY, serialized_loaded.encode("utf-8"), hashlib.sha256).hexdigest()
    
    if hmac.compare_digest(loaded_sig, computed_sig):
        print("Verification SUCCESS: MVP shared-secret provenance signature is valid.")
        # Re-verify file checksums
        all_checksums_valid = True
        for path, expected_hash in loaded_manifest["artifacts"].items():
            actual_hash = hash_file(path)
            if actual_hash != expected_hash:
                print(f"  * Checksum mismatch for file: {path} (Expected: {expected_hash}, Actual: {actual_hash})")
                all_checksums_valid = False
        if all_checksums_valid:
            print("Verification SUCCESS: All build artifact hashes are verified.")
            return 0
        else:
            print("Verification FAILED: Artifact hash mismatch detected.")
            return 1
    else:
        print("Verification FAILED: Invalid provenance signature.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
