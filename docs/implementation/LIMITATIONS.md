# Tempris Accepted Implementation Limitations

This document records the accepted architectural, infrastructure, and tool limitations for the Tempris MVP.

---

## 1. Content Security Policy (SEC-H2)
- **Classification:** `COMPLETE_WITH_LIMITATION / BLOCKED_FRONTEND_SOURCE`
- **Description:** The FastAPI backend implements strict CSP headers (`script-src 'self'`), removing `unsafe-inline` references. However, because the React frontend source code is compiled and stored as a static deployment tarball (`_deploy_frontend.tar.gz`) without editable source directories in this repository, direct validation of the user interface functionality under strict CSP headers could not be safely modified or verified dynamically. 

---

## 2. Dependency Vulnerability Scanner (SDLC-S01)
- **Classification:** `COMPLETE_WITH_LIMITATION / LOCAL_ENV_RESTRICTION`
- **Description:** The `scan_dependencies.py` wrapper invokes the real `pip-audit` scanner. However, as the local development environment runs on a global Python host without a project-isolated virtual environment, `pip-audit` cannot be globally installed on the local system due to strict policies prohibiting arbitrary global modifications.
- **Local Fallback:** A local simulation flag (`SCAN_MOCK_FALLBACK=1`) is provided to test the exception mapping and exit status processing logic of the wrapper script locally. The CI/CD pipelines are fully configured to run the actual scanner in environments where dependencies are installed in isolated containers.

---

## 3. Credentials & Secret Scanner (SDLC-S02)
- **Classification:** `COMPLETE_WITH_LIMITATION / LOCAL_ENV_RESTRICTION`
- **Description:** The `scan_secrets.py` wrapper invokes Gitleaks. However, `gitleaks` is not pre-installed on the local system host. 
- **Local Fallback:** Simulating the scan via `SCAN_MOCK_FALLBACK=1` is supported for testing local wrapper logic. The CI/CD environment is configured with pinned runner binaries to enforce Gitleaks compliance over all commits.

---

## 4. PDF Report Generation (REPORT-C08)
- **Classification:** `COMPLETE_WITH_LIMITATION / PDF_DEPENDENCY_MISSING`
- **Description:** Safe, native PDF layout generation engines (e.g., ReportLab, WeasyPrint) require complex C-libraries (such as Pango, cairo) that are missing on the local VPS/Windows host environments. 
- **Local Fallback:** Generating reports in PDF format is blocked and throws a clean `PDF_GENERATION_BLOCKED` validation error. All compliance requirements are met via fully supported, versioned structured exports in JSON and CSV formats.

---

## 5. Adversary Emulation Engine (AEV-A01 / AEV-D04)
- **Classification:** `COMPLETE_WITH_LIMITATION / AEV_DISABLED`
- **Description:** The AEV engine is globally disabled. No behavior is assigned to ATLAS, APOLLO, HELIOS, ORION, or TARA AI. All run, execution, and authorization endpoints return a `400 AEV_DISABLED` validation status. Only module definition template files exist.

---

## 6. Build Provenance Signing (SDLC-S04)
- **Classification:** `COMPLETE_WITH_LIMITATION / MVP_SHARED_SECRET_AUTHENTICATION`
- **Description:** The SDLC-S04 build provenance signer uses a symmetric HMAC-SHA256 secret key signature to provide manifest verification and build file integrity checks. It is not equivalent to full identity-backed public key signature infrastructure (e.g., using Sigstore/Cosign).
- **Future Migration:** A future upgrade will migrate this to Sigstore/Cosign or another approved public key infrastructure matching enterprise deployment identity providers once available.
