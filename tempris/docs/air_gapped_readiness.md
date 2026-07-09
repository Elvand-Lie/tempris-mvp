# Tempris Air-Gapped & On-Premises Readiness Evaluation

## Executive Summary
This document evaluates the readiness of the Tempris CTEM platform for deployment in fully air-gapped or restricted on-premises environments (e.g., government, defense, critical infrastructure). Overall, the core architecture is highly portable (Dockerized Python/React/Postgres/Redis), but several critical dependencies on external internet access must be remediated to achieve true air-gapped capability.

---

## 1. Current Architecture Portability
✅ **Strengths for On-Premise:**
- **Containerization:** The entire application (frontend, backend, database, cache, message broker) is fully containerized using Docker and `docker-compose`.
- **Database:** PostgreSQL runs locally within the container network; no managed cloud database dependencies (like RDS) are hardcoded.
- **Frontend SPA:** The React frontend is served as static files by the FastAPI backend, requiring no external CDN for core application delivery.
- **State Management:** Redis and Kafka are bundled in the compose stack.

---

## 2. Air-Gapped Blockers (External Dependencies)

### Blocker 1: AI Capabilities (FreeLLMAPI Dependency)
- **Component:** SPEAK chatbot and SPOTLIGHT report generator.
- **Issue:** The platform currently relies on an external API (`http://localhost:3001/v1` proxying to external LLMs) via the `FREELLM_API_KEY`.
- **Air-Gapped Solution:** 
  - Deploy a local open-source LLM (e.g., Llama 3 8B, Mistral 7B) using Ollama or vLLM within the Docker stack.
  - The `FREELLM_BASE_URL` environment variable is already configurable in `docker-compose.prod.yml`, making it easy to point to a local inference endpoint.
  - *Hardware requirement:* The on-prem host must have sufficient GPU resources (e.g., NVIDIA L4 or A10G) to run the model with acceptable latency.

### Blocker 2: CISA KEV & Vulnerability Intelligence Feeds
- **Component:** SCOUT scanner and SPECTRUM triage.
- **Issue:** Vulnerability data (CVE databases, CISA KEV catalog) requires regular updates from the internet to remain relevant.
- **Air-Gapped Solution:** 
  - Implement a "sneakernet" update mechanism.
  - Create a secure import endpoint/script that allows administrators to upload JSON/CSV dumps of the CISA KEV catalog and NVD feeds via USB or secure local transfer.

### Blocker 3: Network Scanning & SSRF Protections
- **Component:** SCOUT scanner (`scanner.py`).
- **Issue:** The recent security hardening strictly blocks scanning of RFC1918 (internal) IPs to prevent SSRF in the cloud deployment. In an on-prem deployment, scanning internal IP ranges is the *primary* use case.
- **Air-Gapped Solution:**
  - Introduce a `DEPLOYMENT_MODE` environment variable.
  - If `DEPLOYMENT_MODE=airgapped` or `on-prem`, bypass the RFC1918 SSRF restriction (while still enforcing role-based access control and audit logging).

### Blocker 4: Package & Dependency Management
- **Component:** Docker build process.
- **Issue:** The current `Dockerfile` relies on `pip install` from PyPI and `npm install` from the public npm registry during the build phase.
- **Air-Gapped Solution:**
  - Pre-build all Docker images on an internet-connected machine.
  - Export images using `docker save` as `.tar` archives.
  - Import them on the air-gapped machine using `docker load`.

---

## 3. Recommended Remediation Roadmap

**Phase 1: Local AI Inference Integration (2 weeks)**
- Package an Ollama container into the `docker-compose` stack.
- Test SPEAK and SPOTLIGHT using a local 7B-8B parameter model.
- Update documentation with GPU hardware requirements.

**Phase 2: Offline Intelligence Sync (1 week)**
- Build an offline update tool for the vulnerability database.
- Add an "Import Threat Intel" UI button in the Admin dashboard.

**Phase 3: Configuration Profiles (1 week)**
- Implement deployment profiles (`CLOUD`, `ON_PREM_RESTRICTED`, `AIR_GAPPED`).
- Adjust SSRF rules and external API calls based on the active profile.

## 4. Conclusion
Tempris is approximately **70% ready** for air-gapped deployment. The primary engineering effort required is swapping the external LLM dependency for a local inference engine and building an offline import mechanism for threat intelligence data. Once completed, the platform can be securely deployed in classified or highly regulated environments.
