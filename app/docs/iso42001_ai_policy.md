# Tempris ISO/IEC 42001:2023 AI Governance Policy

**Version:** 1.0  
**Effective Date:** June 3, 2026  
**Policy Owner:** Chief Security & Risk Officer (CSRO)

---

## 1. Purpose & Scope
This policy governs the development, deployment, and operational use of Artificial Intelligence (AI) systems within the Tempris Continuous Threat Exposure Management (CTEM) platform. It aligns with the requirements of ISO/IEC 42001:2023 (Information Technology – Artificial Intelligence Management System) and applicable Singapore regulatory frameworks, including the Personal Data Protection Act (PDPA), MAS Technology Risk Management (TRM) Guidelines, MAS FEAT Principles, and the IMDA AI Governance Framework v2.

This policy applies to all internal stakeholders and third-party vendors interacting with Tempris AI modules.

## 2. AI Policy Statement (Clause 5.2)
Tempris is committed to the responsible, ethical, and secure use of AI to enhance cybersecurity posture management. We adhere to the following core principles:
- **Fairness:** Ensuring AI vulnerability assessments do not introduce bias.
- **Transparency:** Clearly indicating when users are interacting with AI or AI-generated content.
- **Accountability:** Maintaining human oversight over all AI outputs; AI remains advisory.
- **Privacy & Security:** Prohibiting the processing of Personally Identifiable Information (PII) within AI prompts and protecting all AI interactions with cryptographic audit trails.

## 3. AI System Inventory (Annex A.6.2.2)
Tempris currently operates two distinct AI systems:

| System | Purpose | Inputs | Outputs | Risk Level | Owner |
|--------|---------|--------|---------|------------|-------|
| **SPEAK** | Interactive chatbot for security posture Q&A, CVE lookup, TES interpretation | CISA KEV catalog, TES scores, TACF audit logs, GRC state, User queries | Natural language responses, Security recommendations | Medium | CSRO |
| **SPOTLIGHT** | AI-generated board-level, CISO, compliance, and insurance risk narratives | TES scores, CISA KEV findings, TACF audit logs, Module health status | Executive summary reports, CISO technical briefs, Compliance gap reports | Medium | CSRO |

## 4. Risk Assessment (Clause 6.1.2)
We conduct regular risk assessments for all AI systems. The primary AI-specific risks and mitigations are tracked in the AI Risk Register (accessible via `/api/grc/ai-risk-register`):
- **Prompt Injection (AIR-001):** Mitigated via system prompt isolation and input sanitization.
- **Hallucination (AIR-002):** Mitigated via Retrieval-Augmented Generation (RAG) strictly grounded in CISA KEV data, and mandatory human review of reports.
- **Data Leakage (AIR-003):** Mitigated by prohibiting PII in context and enforcing role-based access control (RBAC).
- **Third-Party Dependency (AIR-004):** Mitigated by maintaining offline fallback engines (e.g., regex-based responses, template-based reports).

*Note: AI Governance maturity directly influences the Tempris Exposure Score (TES) via the AI Governance Modifier (AGM) in the GRC module.*

## 5. Data Quality Requirements (Annex A.7.4)
AI systems rely on high-quality, verified data.
- **Data Sources:** AI context is populated exclusively from validated sources (CISA KEV catalog, immutable TACF audit logs, deterministic TES scores).
- **Sanitization:** All inputs are sanitized before being passed to LLM endpoints.
- **PII Prohibition:** The platform architecture ensures no PII or sensitive client infrastructure data is processed by the AI systems.

## 6. Responsible AI Use (Annex A.9.2)
- **Human Oversight:** AI outputs in Tempris (SPEAK, SPOTLIGHT) are strictly advisory. No automated mitigation actions or configuration changes can be triggered by AI.
- **Auditability:** All AI interactions (user queries, generated reports) are logged to the Tempris Audit & Control Framework (TACF), ensuring a cryptographically verifiable, append-only history of AI usage.

## 7. Third-Party AI Alignment (Annex A.10.3)
Tempris utilizes third-party LLMs (e.g., via FreeLLMAPI) to power generative features.
- **Data Privacy:** Contracts and configurations guarantee that no Tempris data or user prompts are used by third parties to train their models.
- **Resilience:** If the third-party API is unavailable or rate-limited, Tempris automatically falls back to deterministic, offline modes to ensure continuous operation.

## 8. Impact Assessment Process (Annex A.5.2)
Before deploying any new AI feature or significantly altering an existing one, a Data Protection Impact Assessment (DPIA) and an AI System Impact Assessment must be completed and approved by the CSRO. Reviews are conducted annually.

## 9. Roles & Responsibilities (Annex A.3.2)
- **AI System Owner (CSRO):** Responsible for the overall AI strategy, risk management, and ISO 42001 compliance.
- **Engineering Team:** Responsible for implementing technical controls, sanitization, and fallback mechanisms.
- **AI Ethics Committee:** Conducts quarterly reviews of AI usage, hallucination rates, and alignment with MAS FEAT principles.

## 10. Monitoring & Audit (Clause 9.2)
- **Continuous Monitoring:** All AI API calls and responses are tracked.
- **Performance Reviews:** Quarterly reviews assess AI accuracy, fallback trigger rates, and hallucination incidents.
- **External Audit:** An annual external audit validates compliance with this policy and ISO 42001 standards.

## 11. Compliance Mapping

| ISO 42001 Control | Implementation | Singapore Regulation | Status |
|-------------------|----------------|----------------------|--------|
| A.2.2 (Policy) | This document | PDPA, MAS FEAT | Implemented |
| A.3.2 (Roles) | CSRO ownership defined | MAS TRM (Sec 4) | Implemented |
| A.5.2 (Impact) | Required DPIA for new AI | PDPA DPIA | Implemented |
| A.6.2.2 (Inventory) | Section 3 above, `/api/grc/ai-inventory` | IMDA AI Gov v2 | Implemented |
| A.7.4 (Data Qual) | CISA KEV grounding, No PII | MAS Notice 655 | Implemented |
| A.9.2 (Resp. Use) | Advisory only, TACF logging | IMDA Model AI Gov | Implemented |
| A.10.3 (Supplier) | No-training clauses, fallbacks | MAS TRM (Sec 9) | Implemented |

---
**Approval Signatures**
- [X] Chief Security & Risk Officer
- [X] Chief Technology Officer
- [X] Legal Counsel

*Revision History: v1.0 - Initial Publication (2026-06-03)*
