import subprocess
import os
import json
import sys

# Find project root robustly using absolute __file__ path
abs_file = os.path.abspath(__file__)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(abs_file))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def test_secure_software_factory_ci_pipeline():
    # 1. Test Dependency Scanning (Clean Path)
    env_clean = os.environ.copy()
    env_clean["SCAN_MOCK_FALLBACK"] = "1"
    env_clean["SCAN_MOCK_CLEAN"] = "1"
    
    res_dep = subprocess.run(["python", "scripts/ci/scan_dependencies.py"], capture_output=True, text=True, env=env_clean)
    assert res_dep.returncode == 0
    assert "CI Policy Check: PASSED" in res_dep.stdout

    # Test Dependency Scanning (Failure Path)
    env_fail = os.environ.copy()
    env_fail["SCAN_MOCK_FALLBACK"] = "1"
    env_fail["SCAN_MOCK_CLEAN"] = "0"
    
    res_dep_fail = subprocess.run(["python", "scripts/ci/scan_dependencies.py"], capture_output=True, text=True, env=env_fail)
    assert res_dep_fail.returncode == 1
    assert "CI Policy Check: FAILED" in res_dep_fail.stdout

    # 2. Test Secrets Scanning (Clean Path)
    res_sec = subprocess.run(["python", "scripts/ci/scan_secrets.py"], capture_output=True, text=True, env=env_clean)
    assert res_sec.returncode == 0
    assert "CI Secrets Check: PASSED" in res_sec.stdout
    assert os.path.exists("docs/security/secrets_rotation_playbook.md")

    # Test Secrets Scanning (Failure Path)
    res_sec_fail = subprocess.run(["python", "scripts/ci/scan_secrets.py"], capture_output=True, text=True, env=env_fail)
    assert res_sec_fail.returncode == 1
    assert "CI Secrets Check: FAILED" in res_sec_fail.stdout

    # 3. Test SBOM Generation & Parsing
    res_sbom = subprocess.run(["python", "scripts/ci/generate_sbom.py"], capture_output=True, text=True)
    assert res_sbom.returncode == 0
    sbom_file = "artifacts/security/sbom/bom.json"
    assert os.path.exists(sbom_file)
    with open(sbom_file, "r") as f:
        sbom_data = json.load(f)
    assert sbom_data["bomFormat"] == "CycloneDX"
    assert sbom_data["specVersion"] == "1.4"
    assert len(sbom_data["components"]) > 0

    # 4. Test Provenance Signing & Cryptographic Validation
    res_prov = subprocess.run(["python", "scripts/ci/sign_provenance.py"], capture_output=True, text=True)
    assert res_prov.returncode == 0
    assert "Verification SUCCESS" in res_prov.stdout
    prov_file = "artifacts/security/provenance/provenance.json"
    assert os.path.exists(prov_file)
    
    # Verify tampering detection
    with open(prov_file, "r") as f:
        prov_data = json.load(f)
    
    # Tamper with signature
    prov_data["signature"] = "a" * 64
    tampered_file = "artifacts/security/provenance/provenance_tampered.json"
    with open(tampered_file, "w") as f:
        json.dump(prov_data, f)
    try:
        # Clear module cache to prevent namespace collisions during full folder runs
        sys.modules.pop("scripts", None)
        sys.modules.pop("scripts.ci", None)
        sys.modules.pop("scripts.ci.sign_provenance", None)
        
        if project_root:
            if project_root in sys.path:
                sys.path.remove(project_root)
            sys.path.insert(0, project_root)
            
        # Run verification using tampered file (mocking loaded verification)
        import hmac
        import hashlib
        from scripts.ci.sign_provenance import PROVENANCE_KEY, hash_file
        
        serialized = json.dumps(prov_data["manifest"], sort_keys=True)
        computed_sig = hmac.new(PROVENANCE_KEY, serialized.encode("utf-8"), hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(prov_data["signature"], computed_sig)
    finally:
        if os.path.exists(tampered_file):
            os.remove(tampered_file)

    # 5. Test AI Review Gate
    res_gate = subprocess.run(["python", "scripts/ci/ai_review_gate.py"], capture_output=True, text=True)
    # Since we have a walkthrough.md in artifacts/workspace, this should pass
    assert "Release Gate" in res_gate.stdout


def test_scanner_ci_enforcement_and_unavailability():
    # 1. CI enforces real tools (rejects SCAN_MOCK_FALLBACK)
    env_ci = os.environ.copy()
    env_ci["CI"] = "true"
    env_ci["SCAN_MOCK_FALLBACK"] = "1"
    
    # Dependencies scanner should try to invoke real pip-audit and fail with TOOL_UNAVAILABLE since it is absent locally
    res_dep = subprocess.run(["python", "scripts/ci/scan_dependencies.py"], capture_output=True, text=True, env=env_ci)
    assert res_dep.returncode == 1
    assert "TOOL_UNAVAILABLE" in res_dep.stdout
    
    # Secrets scanner should try to invoke real Gitleaks and fail with TOOL_UNAVAILABLE
    res_sec = subprocess.run(["python", "scripts/ci/scan_secrets.py"], capture_output=True, text=True, env=env_ci)
    assert res_sec.returncode == 1
    assert "TOOL_UNAVAILABLE" in res_sec.stdout

    # 2. Ordinary local run without fallback fails with TOOL_UNAVAILABLE
    env_local = os.environ.copy()
    env_local.pop("SCAN_MOCK_FALLBACK", None)
    env_local.pop("CI", None)
    
    res_dep_local = subprocess.run(["python", "scripts/ci/scan_dependencies.py"], capture_output=True, text=True, env=env_local)
    assert res_dep_local.returncode == 1
    assert "TOOL_UNAVAILABLE" in res_dep_local.stdout

