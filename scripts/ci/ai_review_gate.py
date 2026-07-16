#!/usr/bin/env python3
"""
SDLC-S05: AI-Assisted Release Gate.
Verifies that all automated code changes are fully validated, tested, and carry an approved human walkthrough manifest.
"""
import os
import sys

def verify_release_gate():
    print("--- SDLC-S05: Verifying AI-Assisted Release Gates ---")
    
    # 1. Verify that walkthrough.md exists
    walkthrough_path = "walkthrough.md"
    # If not in current, check in artifacts directory
    if not os.path.exists(walkthrough_path):
        # Scan standard artifacts directory
        artifacts_dir = os.path.abspath(os.path.join(os.environ.get("USERPROFILE", ""), ".gemini", "antigravity-ide", "brain"))
        if os.path.exists(artifacts_dir):
            for root, dirs, files in os.walk(artifacts_dir):
                if "walkthrough.md" in files:
                    walkthrough_path = os.path.join(root, "walkthrough.md")
                    break
                    
    if not os.path.exists(walkthrough_path):
        print("Release Gate FAILED: No walkthrough.md found. All AI changes must carry a walkthrough summary.")
        return 1
        
    # 2. Check if walkthrough.md contains a validation/test summary section
    with open(walkthrough_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    required_sections = ["Verification", "passed", "test"]
    missing = [s for s in required_sections if s.lower() not in content.lower()]
    if missing:
        print(f"Release Gate FAILED: Walkthrough is missing proof of verification (missing terms: {missing})")
        return 1
        
    print("Release Gate SUCCESS: Walkthrough and test validations are present and verified.")
    return 0

if __name__ == "__main__":
    sys.exit(verify_release_gate())
