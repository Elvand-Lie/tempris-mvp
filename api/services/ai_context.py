"""
Unified AI Context Builder
Collects data from ALL Tempris modules to provide SPEAK and SPOTLIGHT
with complete platform awareness.
Includes RAG (Retrieval-Augmented Generation) via ChromaDB vector search.
"""
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session

logger = logging.getLogger("tempris.ai_context")


def build_full_context(db: Session) -> dict:
    """Build a comprehensive context dict from every Tempris module.
    
    Returns:
        dict with keys:
            - full_text: str  (for LLM system prompt injection)
            - structured: dict (for mock/fallback data-aware responses)
    """
    sections = []
    structured = {}

    # ── 1. SPECTRUM — TES Score ───────────────────────────────────────────────
    try:
        from routers.synthesis import get_dashboard_data
        dashboard = get_dashboard_data()
        tes_score = dashboard.get("aggregate_tes", 0)
        module_health = dashboard.get("module_health", [])
        alerts = dashboard.get("alerts", [])

        health_text = ", ".join([f"{m['name']}={m['status']}" for m in module_health])
        alerts_text = "\n".join([f"  - [{a.get('type','info').upper()}] {a['module']}: {a['message']}" for a in alerts])

        sections.append(f"""═══ SPECTRUM — Threat Exposure Score ═══
• Aggregate TES: {tes_score:.1f} / 10.0 ({'CRITICAL' if tes_score >= 7 else 'HIGH' if tes_score >= 5 else 'MEDIUM' if tes_score >= 3 else 'LOW'})
• Module Health: {health_text}

Active Alerts:
{alerts_text if alerts_text else '  (none)'}""")

        structured["tes_score"] = tes_score
        structured["module_health"] = module_health
        structured["alerts"] = alerts
    except Exception as e:
        logger.warning(f"Context: SPECTRUM failed: {e}")

    # ── 2. SCOUT KEV — Vulnerability Intelligence ────────────────────────────
    try:
        from services.kev_loader import get_all_findings
        all_findings = get_all_findings()
        total = len(all_findings)
        ransomware_findings = [f for f in all_findings if f.get("ransomware")]
        critical_findings = [f for f in all_findings if f.get("priority") == "P0"]
        high_findings = [f for f in all_findings if f.get("priority") == "P1"]

        top5 = ""
        for f in critical_findings[:5]:
            top5 += f"  - {f['cve']}: {f['title']} (Vendor: {f.get('vendor','?')}, CVSS: {f.get('cvss',0)}, Ransomware: {f.get('ransomware', False)})\n"

        sections.append(f"""═══ SCOUT — CISA KEV Vulnerability Intelligence ═══
• Total Known Exploited Vulnerabilities: {total:,}
• Critical (P0): {len(critical_findings):,}
• High (P1): {len(high_findings):,}
• Ransomware-linked: {len(ransomware_findings):,}

Top 5 Critical CVEs:
{top5.rstrip()}""")

        structured["kev_total"] = total
        structured["kev_critical"] = len(critical_findings)
        structured["kev_ransomware"] = len(ransomware_findings)
        structured["kev_top5"] = critical_findings[:5]
        structured["all_findings"] = all_findings
    except Exception as e:
        logger.warning(f"Context: SCOUT KEV failed: {e}")

    # ── 3. ASSET INVENTORY ───────────────────────────────────────────────────
    try:
        from models import Asset
        assets = db.query(Asset).filter(Asset.status == "active").all()
        total_assets = len(assets)

        by_type = {}
        by_criticality = {}
        for a in assets:
            by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
            by_criticality[a.criticality] = by_criticality.get(a.criticality, 0) + 1

        type_text = ", ".join([f"{k}: {v}" for k, v in sorted(by_type.items())])
        crit_text = ", ".join([f"{k}: {v}" for k, v in sorted(by_criticality.items())])

        asset_lines = ""
        critical_assets = [a for a in assets if a.criticality == "critical"]
        for a in critical_assets[:10]:
            asset_lines += f"  - [{a.id}] {a.name} ({a.asset_type}) — IP: {a.ip_address or 'N/A'}, Owner: {a.owner or 'N/A'}\n"

        sections.append(f"""═══ ASSET INVENTORY ═══
• Total Active Assets: {total_assets}
• By Type: {type_text}
• By Criticality: {crit_text}

Critical Assets:
{asset_lines.rstrip() if asset_lines else '  (none)'}""")

        structured["asset_count"] = total_assets
        structured["assets_by_type"] = by_type
        structured["assets_by_criticality"] = by_criticality
        structured["critical_assets"] = [{"id": a.id, "name": a.name, "type": a.asset_type, "ip": a.ip_address} for a in critical_assets]
    except Exception as e:
        logger.warning(f"Context: ASSET failed: {e}")

    # ── 4. SCANNER FINDINGS ──────────────────────────────────────────────────
    try:
        from models import ScanFinding
        scan_findings = db.query(ScanFinding).order_by(ScanFinding.discovered_at.desc()).limit(50).all()
        total_scans = len(scan_findings)

        by_risk = {}
        for sf in scan_findings:
            risk = sf.risk or "info"
            by_risk[risk] = by_risk.get(risk, 0) + 1

        risk_text = ", ".join([f"{k}: {v}" for k, v in sorted(by_risk.items())])

        scan_lines = ""
        for sf in scan_findings[:8]:
            scan_lines += f"  - [{sf.risk or 'info'}] {sf.target}:{sf.port} — {(sf.detail or '')[:80]}\n"

        sections.append(f"""═══ SCOUT SCANNER — Recent Scan Findings ═══
• Recent Findings: {total_scans}
• By Risk: {risk_text if risk_text else 'none'}

Latest Findings:
{scan_lines.rstrip() if scan_lines else '  No scans recorded yet.'}""")

        structured["scan_count"] = total_scans
        structured["scans_by_risk"] = by_risk
    except Exception as e:
        logger.warning(f"Context: SCANNER failed: {e}")

    # ── 5. STRIKE — Adversary Simulations ────────────────────────────────────
    try:
        from models import StrikeSimulation, StrikeAuthorization
        latest_sim = db.query(StrikeSimulation).order_by(
            StrikeSimulation.started_at.desc()
        ).first()

        if latest_sim and latest_sim.results:
            results = latest_sim.results if isinstance(latest_sim.results, list) else []
            exploitable = [r for r in results if r.get("result") == "exploitable"]
            blocked = [r for r in results if r.get("result") == "blocked"]

            technique_lines = ""
            for r in results[:10]:
                status_icon = "🔴" if r.get("result") == "exploitable" else "🟢" if r.get("result") == "blocked" else "⚪"
                technique_lines += f"  - {status_icon} {r.get('technique_id','?')}: {r.get('technique_name','?')} — {r.get('result','?')} (confidence: {r.get('confidence', 0):.0%})\n"

            # Get auth info
            auth = db.query(StrikeAuthorization).filter(
                StrikeAuthorization.id == latest_sim.authorization_id
            ).first()
            target_name = auth.target_name if auth else "Unknown"
            target_ip = auth.target_ip if auth else "Unknown"

            sections.append(f"""═══ STRIKE — Adversary Emulation Results ═══
• Latest Simulation: {latest_sim.id}
• Target: {target_name} ({target_ip})
• Status: {latest_sim.status}
• Techniques Tested: {len(results)}
• Exploitable: {len(exploitable)} | Blocked: {len(blocked)}

Technique Breakdown:
{technique_lines.rstrip()}""")

            structured["strike_sim_id"] = latest_sim.id
            structured["strike_target"] = target_name
            structured["strike_exploitable"] = len(exploitable)
            structured["strike_blocked"] = len(blocked)
            structured["strike_results"] = results
        else:
            sections.append("═══ STRIKE — Adversary Emulation ═══\n• No simulations have been run yet.")
            structured["strike_sim_id"] = None
    except Exception as e:
        logger.warning(f"Context: STRIKE failed: {e}")

    # ── 6. STANDARD — Compliance Frameworks ──────────────────────────────────
    try:
        from routers.standard import FRAMEWORKS
        from models import ControlStatus

        all_statuses = db.query(ControlStatus).all()
        status_map = {}
        for cs in all_statuses:
            status_map[(cs.framework_id, cs.control_id)] = cs.status

        framework_lines = ""
        total_controls = 0
        total_compliant = 0
        total_non_compliant = 0
        non_compliant_list = []

        for fw_id, fw in FRAMEWORKS.items():
            controls = fw["controls"]
            compliant = 0
            non_comp = 0
            for c in controls:
                status = status_map.get((fw_id, c["id"]), c.get("default_status", "not_assessed"))
                total_controls += 1
                if status == "compliant":
                    compliant += 1
                    total_compliant += 1
                elif status == "non_compliant":
                    non_comp += 1
                    total_non_compliant += 1
                    non_compliant_list.append(f"{fw['name']} — {c['id']}: {c['title']}")
            pct = round(compliant / max(len(controls), 1) * 100)
            framework_lines += f"  - {fw['name']}: {compliant}/{len(controls)} compliant ({pct}%)\n"

        nc_text = ""
        for nc in non_compliant_list[:10]:
            nc_text += f"  - ⚠ {nc}\n"

        sections.append(f"""═══ STANDARD — Regulatory Compliance ═══
• Frameworks Tracked: {len(FRAMEWORKS)}
• Total Controls: {total_controls} | Compliant: {total_compliant} | Non-compliant: {total_non_compliant}

Framework Scores:
{framework_lines.rstrip()}

Non-compliant Controls:
{nc_text.rstrip() if nc_text else '  All controls compliant.'}""")

        structured["compliance_total_controls"] = total_controls
        structured["compliance_compliant"] = total_compliant
        structured["compliance_non_compliant"] = total_non_compliant
        structured["compliance_gaps"] = non_compliant_list
    except Exception as e:
        logger.warning(f"Context: STANDARD failed: {e}")

    # ── 7. GRC — ISO/IEC 42001:2023 AI Governance ───────────────────────────
    try:
        from models import GrcState, GrcSignoff
        from routers.grc import GRC_CONTROLS, _calc_composite_tes

        grc_state = db.query(GrcState).order_by(GrcState.id.desc()).first()
        toggles = grc_state.toggles if grc_state and grc_state.toggles else {}
        sop_state = grc_state.sop_state if grc_state and grc_state.sop_state else []
        grc_tes = _calc_composite_tes(toggles) if toggles else {"score": 0, "band": "N/A", "agm": 0, "drf": 0, "tef": 0}

        # Build control status from SOP state
        sop_map = {s["id"]: s for s in sop_state} if sop_state else {}
        signoffs = db.query(GrcSignoff).all()
        signoff_map = {}
        for so in signoffs:
            signoff_map.setdefault(so.control_id, []).append(so.signoff_type)

        control_lines = ""
        for c in GRC_CONTROLS:
            sop = sop_map.get(c["id"], {})
            pic = sop.get("pic", "Unassigned")
            eu = "✅" if sop.get("endUserAgreed") else "❌"
            pa = "✅" if sop.get("picAgreed") else "❌"
            control_lines += f"  - {c['id']} ({c['domain']}): {c['title']} | PIC: {pic or 'Unassigned'} | End-user: {eu} | PIC Agreed: {pa}\n"

        sections.append(f"""═══ GRC — ISO/IEC 42001:2023 AI Governance ═══
• Composite TES: {grc_tes['score']} ({grc_tes['band']})
• AGM (AI Governance Modifier): {grc_tes.get('agm', 'N/A')}
• DRF (Data Readiness Factor): {grc_tes.get('drf', 'N/A')}
• TEF (Third-party Exposure Factor): {grc_tes.get('tef', 'N/A')}

ISO 42001 Control Status:
{control_lines.rstrip()}""")

        structured["grc_tes"] = grc_tes
        structured["grc_controls"] = GRC_CONTROLS
    except Exception as e:
        logger.warning(f"Context: GRC failed: {e}")

    # ── 8. EDIP Decisions ────────────────────────────────────────────────────
    try:
        from models import EdipDecision
        recent_edip = db.query(EdipDecision).order_by(EdipDecision.decided_at.desc()).limit(15).all()

        if recent_edip:
            by_decision = {}
            for d in recent_edip:
                by_decision[d.decision] = by_decision.get(d.decision, 0) + 1

            decision_text = ", ".join([f"{k}: {v}" for k, v in sorted(by_decision.items())])
            edip_lines = ""
            for d in recent_edip[:8]:
                edip_lines += f"  - {d.cve or d.finding_id}: {d.decision.upper()} by {d.decided_by or 'auto'} — {(d.rationale or 'No rationale')[:60]}\n"

            sections.append(f"""═══ EDIP — Exposure Decision Intelligence ═══
• Recent Decisions (last 15): {decision_text}

Recent EDIP Actions:
{edip_lines.rstrip()}""")

            structured["edip_recent"] = [{"cve": d.cve, "decision": d.decision, "by": d.decided_by} for d in recent_edip[:8]]
        else:
            sections.append("═══ EDIP — Exposure Decision Intelligence ═══\n• No EDIP decisions recorded yet.")
    except Exception as e:
        logger.warning(f"Context: EDIP failed: {e}")

    # ── 9. TACF — Audit Trail ────────────────────────────────────────────────
    try:
        from models import AuditLog
        audit_logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(20).all()

        audit_lines = ""
        for log in audit_logs:
            ts = log.timestamp.strftime("%Y-%m-%d %H:%M") if log.timestamp else "?"
            audit_lines += f"  - [{ts}] {log.module}: {log.action} — {(log.detail or '')[:80]}\n"

        sections.append(f"""═══ TACF — Audit Trail ═══
• Recent Entries: {len(audit_logs)}

{audit_lines.rstrip()}""")

        structured["audit_count"] = len(audit_logs)
    except Exception as e:
        logger.warning(f"Context: TACF failed: {e}")

    # ── Combine ──────────────────────────────────────────────────────────────
    full_text = "\n\n".join(sections)

    return {
        "full_text": full_text,
        "structured": structured,
    }


def retrieve_rag_context(query: str, n_results: int = 5) -> str:
    """Retrieve semantically relevant knowledge chunks from the vector database."""
    try:
        from services.rag_engine import semantic_search
        results = semantic_search(query, n_results=n_results)
        if not results:
            return ""
        
        rag_text = "\n═══ RAG — Relevant Knowledge Base Results ═══\n"
        for i, r in enumerate(results, 1):
            source = r.get("source", "unknown")
            score = r.get("score", 0)
            text = r.get("text", "")[:400]  # Limit each chunk to 400 chars
            rag_text += f"\n[{i}] Source: {source} (relevance: {score:.2f})\n{text}\n"
        
        return rag_text
    except Exception as e:
        logger.warning(f"RAG retrieval failed: {e}")
        return ""


def build_speak_system_prompt(context_text: str, relevant_text: str = "", rag_text: str = "") -> str:
    """Build the SPEAK AI system prompt with full context + RAG results."""
    return f"""You are SPEAK, the Tempris AI Security Assistant — the intelligent nerve center of the Tempris CTEM (Continuous Threat Exposure Management) platform.

You have FULL ACCESS to all real-time platform data across every module:
- SPECTRUM (TES scores), SCOUT (CISA KEV + scanner), STRIKE (adversary simulations)
- STANDARD (8 regulatory frameworks), GRC (ISO 42001 AI governance)
- EDIP (exposure decisions), TACF (audit trail), Asset Inventory

You also have access to a semantic knowledge base (RAG) containing policy documents,
compliance frameworks, and historical security data for precision retrieval.

{context_text}
{relevant_text}
{rag_text}

Guidelines:
- Be concise, technical, and actionable.
- Reference specific CVEs, TES scores, asset IDs, control IDs, or framework names when relevant.
- If asked about compliance, reference specific framework controls and their status.
- If asked about risk, reference STRIKE simulation results and EDIP decisions.
- If asked about assets, provide asset IDs, types, criticality levels.
- When RAG results are provided, prioritize that precise knowledge over general context.
- Always ground answers in the data above — never make up CVEs or scores."""


def build_spotlight_prompt(context_text: str, report_type: str) -> str:
    """Build the SPOTLIGHT report generation prompt with full context."""
    report_intros = {
        "executive": """You are SPOTLIGHT, the Tempris executive reporting engine.
Generate a board-level executive summary. Structure it as:
1. Current Security Posture (TES score interpretation, module health)
2. Key Risk Highlights (top CVEs, STRIKE findings, compliance gaps)
3. Asset Exposure (critical assets, scanner findings)
4. Regulatory Standing (compliance framework scores)
5. Recommended Actions (prioritized by risk)

Write for a non-technical board audience. Use business impact language.""",

        "ciso": """You are SPOTLIGHT generating a CISO Technical Summary.
Structure it as:
1. Threat Landscape Overview (KEV statistics, EDIP decisions)
2. Attack Surface Analysis (scanner findings, STRIKE simulation results)
3. Vulnerability Prioritization (top CVEs with CVSS, ransomware linkage)
4. Infrastructure Risk (asset inventory, critical asset exposure)
5. Compliance Technical Gaps (specific non-compliant controls per framework)
6. Remediation Priorities (ranked action items with SLAs)

Write for a technical CISO audience. Reference specific CVEs, techniques, and controls.""",

        "compliance": """You are SPOTLIGHT generating a Compliance Audit Report.
Structure it as:
1. Regulatory Compliance Summary (all 8 frameworks with scores)
2. Non-compliant Controls (specific control IDs and gaps)
3. ISO/IEC 42001:2023 AI Governance Status (GRC composite TES, control signoffs)
4. MAS TRM Compliance (specific clause analysis)
5. PDPA / IM8A Status
6. Remediation Timeline (SLA-aligned action items)
7. Evidence Summary (evidence upload status per framework)

Write for a regulatory auditor. Reference specific clauses and control IDs.""",

        "insurance": """You are SPOTLIGHT generating a Cyber Insurance Risk Assessment.
Structure it as:
1. Organization Risk Profile (TES score, aggregate exposure)
2. Ransomware Exposure Quantification (KEV ransomware-linked count, STRIKE results)
3. Attack Surface Metrics (open ports, exploitable techniques, asset criticality)
4. Security Controls Effectiveness (compliance scores, EDIP decision patterns)
5. Incident Response Readiness (MAS TRM 12.1.1, TACF audit integrity)
6. Risk Recommendation (insurance tier suggestion based on metrics)

Write for an insurance underwriter. Use quantified risk metrics.""",
    }

    intro = report_intros.get(report_type, report_intros["executive"])
    return f"""{intro}

{context_text}

Generate the report now based on the live data above. Be comprehensive and data-driven."""
