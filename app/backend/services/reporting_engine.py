"""
REPORT-C08: Tenant-scoped Reporting Engine.
Generates CSV and JSON reports for Spectrum risk, Standard gap, and audit evidence packages.
Stores versioned manifest records in the database.
"""
from sqlalchemy.orm import Session
from models import GeneratedReport, Finding, ControlEvidence, AuditLog
from routers.audit import append_to_audit_log_db, AuditEntry
from datetime import datetime, timezone
import hashlib
import json
import uuid
import os

def generate_report_pipeline(
    db: Session,
    tenant_id: str,
    report_type: str,  # risk, gap, evidence, combined, pdf, json
    requested_by: str,
    approved_by: str | None = None,
    source_finding_ids: list[str] = [],
    source_evidence_ids: list[str] = [],
    framework_configuration: dict = {}
) -> dict:
    
    if report_type.lower() == "pdf":
        raise ValueError("PDF_GENERATION_BLOCKED: Safe native PDF layout dependencies (e.g. reportlab, weasyprint) are absent/disabled.")

    # 1. Gather findings & evidence records scoped to tenant
    findings = db.query(Finding).filter(
        Finding.id.in_(source_finding_ids)
    ).all()
    # Filter findings by tenant_id to prevent cross-tenant extraction
    findings = [f for f in findings if f.tenant_id == tenant_id]
    
    evidence_ids_int = []
    for eid in source_evidence_ids:
        try:
            evidence_ids_int.append(int(eid))
        except ValueError:
            pass
            
    evidences = db.query(ControlEvidence).filter(
        ControlEvidence.id.in_(evidence_ids_int)
    ).all()
    evidences = [e for e in evidences if e.tenant_id == tenant_id]
    
    # 2. Build Report Content (with absolute scoring internals redaction)
    report_data = {
        "report_type": report_type,
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "evidence": []
    }
    
    for f in findings:
        # EXCLUDE scoring internals like raw_inputs, agm, drf, tef, sss_data, etc.
        report_data["findings"].append({
            "id": f.id,
            "cve": f.cve,
            "title": f.title,
            "vendor": f.vendor,
            "product": f.product,
            "cvss": f.cvss,
            "priority": f.priority,
            "status": f.status,
            "short_description": f.short_description
        })
        
    for e in evidences:
        report_data["evidence"].append({
            "id": e.id,
            "framework_id": e.framework_id,
            "control_id": e.control_id,
            "filename": e.filename
        })
        
    report_id = f"REP-{uuid.uuid4().hex[:8].upper()}"
    os.makedirs("backups/reports", exist_ok=True)

    if report_type == "combined":
        # Generate risk report
        risk_rows = ["Finding ID,CVE,Title,Vendor,Product,CVSS,Priority,Status"]
        for f in report_data["findings"]:
            risk_rows.append(f"{f['id']},{f['cve'] or 'N/A'},\"{f['title']}\",\"{f['vendor']}\",\"{f['product']}\",{f['cvss']},{f['priority']},{f['status']}")
        risk_csv = "\n".join(risk_rows)
        risk_path = f"backups/reports/{report_id}_risk.csv"
        with open(risk_path, "w", encoding="utf-8") as f_out:
            f_out.write(risk_csv)
        risk_hash = hashlib.sha256(risk_csv.encode("utf-8")).hexdigest()

        # Generate gap report
        gap_rows = ["Framework ID,Control ID,Filename"]
        for e in report_data["evidence"]:
            gap_rows.append(f"{e['framework_id']},{e['control_id']},\"{e['filename']}\"")
        gap_csv = "\n".join(gap_rows)
        gap_path = f"backups/reports/{report_id}_gap.csv"
        with open(gap_path, "w", encoding="utf-8") as f_out:
            f_out.write(gap_csv)
        gap_hash = hashlib.sha256(gap_csv.encode("utf-8")).hexdigest()

        # Master manifest JSON mapping
        manifest_data = {
            "report_id": report_id,
            "tenant_id": tenant_id,
            "engagement_id": framework_configuration.get("engagement_id", "ENG-DEFAULT"),
            "report_type": "combined",
            "generator_version": "v2.1.0",
            "requested_by": requested_by,
            "approved_by": approved_by,
            "source_finding_ids": [f.id for f in findings],
            "source_evidence_ids": [str(e.id) for e in evidences],
            "framework_configuration": framework_configuration,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "sub_reports": {
                "risk": {
                    "path": risk_path,
                    "content_hash": risk_hash,
                    "format": "csv"
                },
                "gap": {
                    "path": gap_path,
                    "content_hash": gap_hash,
                    "format": "csv"
                }
            }
        }
        json_content = json.dumps(manifest_data, sort_keys=True, indent=2)
        content_hash = hashlib.sha256(json_content.encode("utf-8")).hexdigest()
        artifact_loc = f"backups/reports/{report_id}_combined.json"
        with open(artifact_loc, "w", encoding="utf-8") as f_out:
            f_out.write(json_content)

    else:
        # JSON content
        json_content = json.dumps(report_data, sort_keys=True, indent=2)
        content_hash = hashlib.sha256(json_content.encode("utf-8")).hexdigest()
        
        # CSV content (for Risk / Gap CSV reports)
        csv_rows = ["Finding ID,CVE,Title,Vendor,Product,CVSS,Priority,Status"]
        for f in report_data["findings"]:
            csv_rows.append(f"{f['id']},{f['cve'] or 'N/A'},\"{f['title']}\",\"{f['vendor']}\",\"{f['product']}\",{f['cvss']},{f['priority']},{f['status']}")
        csv_content = "\n".join(csv_rows)
        
        artifact_loc = f"backups/reports/{report_id}.json"
        if report_type in ("risk", "gap"):
            artifact_loc = f"backups/reports/{report_id}.csv"
            with open(artifact_loc, "w", encoding="utf-8") as f_out:
                f_out.write(csv_content)
        else:
            with open(artifact_loc, "w", encoding="utf-8") as f_out:
                f_out.write(json_content)

    # 3. Create Manifest DB Record
    report_record = GeneratedReport(
        id=report_id,
        tenant_id=tenant_id,
        engagement_id=framework_configuration.get("engagement_id", "ENG-DEFAULT"),
        report_type=report_type,
        generator_version="v2.1.0",
        requested_by=requested_by,
        approved_by=approved_by,
        source_finding_ids=[f.id for f in findings],
        source_evidence_ids=[str(e.id) for e in evidences],
        framework_configuration=framework_configuration,
        content_hash=content_hash,
        artifact_location=artifact_loc
    )
    db.add(report_record)
    
    append_to_audit_log_db(db, AuditEntry(
        user=requested_by,
        action="REPORT_GENERATED",
        module="SYNTHESIS",
        detail=f"Successfully generated {report_type} report {report_id} with hash {content_hash}."
    ))
    db.commit()
    db.refresh(report_record)
    
    return {
        "report_id": report_id,
        "manifest": {
            "id": report_record.id,
            "tenant_id": report_record.tenant_id,
            "engagement_id": report_record.engagement_id,
            "report_type": report_record.report_type,
            "generator_version": report_record.generator_version,
            "requested_by": report_record.requested_by,
            "approved_by": report_record.approved_by,
            "source_finding_ids": report_record.source_finding_ids,
            "source_evidence_ids": report_record.source_evidence_ids,
            "framework_configuration": report_record.framework_configuration,
            "content_hash": report_record.content_hash,
            "artifact_location": report_record.artifact_location
        }
    }
