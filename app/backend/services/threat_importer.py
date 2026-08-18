"""
THREAT-T01: Versioned Idempotent Threat Importer.
Parses, validates, and imports threat-packs into generic database models with dry-run support.
"""
from sqlalchemy.orm import Session
from models import CanonicalVulnerability, Finding, FindingRelationship, FindingSource, FindingControl, AuditLog
from routers.audit import append_to_audit_log_db, AuditEntry
from services.cve_intelligence import validate_and_normalize_cve
from datetime import datetime, timedelta, timezone

def import_threat_pack(db: Session, pack_data: dict, dry_run: bool = False, requested_by: str = "system:threat-importer") -> dict:
    pack_name = pack_data.get("pack_name")
    version = pack_data.get("version", "1.0.0")
    
    if not pack_name:
        raise ValueError("pack_name is required in threat pack.")
        
    source_tag = f"threat_pack:{pack_name}:{version}"
    
    # 1. Validation
    findings_data = pack_data.get("findings", [])
    relationships_data = pack_data.get("relationships", [])
    
    errors = []
    validated_findings = []
    
    # Track existing findings to prevent duplicate imports inside same pack
    seen_ids = set()
    
    for f in findings_data:
        fid = f.get("id")
        if not fid:
            errors.append("Finding record is missing 'id'.")
            continue
        if fid in seen_ids:
            errors.append(f"Duplicate finding id '{fid}' in threat pack.")
            continue
        seen_ids.add(fid)
        
        # Freshness verification
        expiry_days = f.get("expiry_days", 365)
        expiry_date = datetime.now(timezone.utc) + timedelta(days=expiry_days)
        
        validated_findings.append({
            "id": fid,
            "tenant_id": f.get("tenant_id", "tempris"),
            "finding_type": f.get("finding_type", "vulnerability"),
            "subtype": f.get("subtype", "CVE"),
            "pipeline": f.get("pipeline", "SYNTHETIC"),
            "verification": f.get("verification", "CONFIRMED"),
            "score": f.get("cvss", 5.0),
            "status": f.get("status", "unmitigated"),
            "cve": f.get("cve"),
            "title": f.get("title", "Unnamed Threat Record"),
            "vendor": f.get("vendor", "Generic Vendor"),
            "product": f.get("product", "Generic Product"),
            "cvss": f.get("cvss", 5.0),
            "priority": f.get("priority", "P2"),
            "short_description": f.get("description", ""),
            "source": source_tag,
            "expiry_date": expiry_date,
            "sources": f.get("sources", []),
            "controls": f.get("controls", [])
        })
        
    if errors:
        return {"status": "failed", "errors": errors}
        
    if dry_run:
        return {
            "status": "dry_run_success",
            "pack_name": pack_name,
            "version": version,
            "findings_to_import": len(validated_findings),
            "relationships_to_import": len(relationships_data)
        }
        
    # 2. Execution (with deduplication)
    imported_findings_count = 0
    for vf in validated_findings:
        # Check and normalize CVE
        raw_cve = vf.get("cve")
        canonical_cve = None
        if raw_cve:
            try:
                canonical_cve = validate_and_normalize_cve(raw_cve)
                canon = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == canonical_cve).first()
                if canon is None:
                    canon = CanonicalVulnerability(
                        cve_id=canonical_cve,
                        status="unknown",
                        description=vf.get("title") or vf.get("short_description"),
                        description_source="THREAT_PACK_IMPORT",
                    )
                    db.add(canon)
                    db.flush()
            except ValueError:
                canonical_cve = None

        # Check if already exists
        existing = db.query(Finding).filter(Finding.id == vf["id"]).first()
        if existing:
            # Update fields (deduplication / version upgrade)
            existing.title = vf["title"]
            existing.cvss = vf["cvss"]
            existing.priority = vf["priority"]
            existing.status = vf["status"]
            existing.verification = vf["verification"]
            existing.source = source_tag
            if canonical_cve and not existing.canonical_cve_id:
                existing.canonical_cve_id = canonical_cve
        else:
            new_f = Finding(
                id=vf["id"],
                tenant_id=vf["tenant_id"],
                canonical_cve_id=canonical_cve,
                finding_type=vf["finding_type"],
                subtype=vf["subtype"],
                pipeline=vf["pipeline"],
                verification=vf["verification"],
                score=vf["score"],
                status=vf["status"],
                cve=vf["cve"],
                title=vf["title"],
                vendor=vf["vendor"],
                product=vf["product"],
                cvss=vf["cvss"],
                priority=vf["priority"],
                short_description=vf["short_description"],
                source=source_tag
            )
            db.add(new_f)
            imported_findings_count += 1
            
        # Import sources
        # Clear existing sources for this finding to be idempotent
        db.query(FindingSource).filter(FindingSource.finding_id == vf["id"]).delete()
        for src in vf["sources"]:
            new_src = FindingSource(
                finding_id=vf["id"],
                source_id=src.get("source_id", "SRC-GENERIC"),
                publisher=src.get("publisher", "Tempris Threat Intel"),
                retrieved_at=datetime.utcnow(),
                last_verified_at=datetime.utcnow(),
                verification_state=src.get("verification_state", "CONFIRMED"),
                expiry_date=vf["expiry_date"],
                analyst_notes=src.get("analyst_notes")
            )
            db.add(new_src)
            
        # Import controls
        db.query(FindingControl).filter(FindingControl.finding_id == vf["id"]).delete()
        for ctrl in vf["controls"]:
            new_ctrl = FindingControl(
                finding_id=vf["id"],
                title=ctrl.get("title", "Remediation Control"),
                description=ctrl.get("description"),
                layer_type=ctrl.get("layer_type", "compensating"),
                priority=ctrl.get("priority", "P1"),
                status=ctrl.get("status", "not_assessed")
            )
            db.add(new_ctrl)

    # Import relationships
    for rel in relationships_data:
        # Deduplicate relationships
        rel_existing = db.query(FindingRelationship).filter(
            FindingRelationship.source_id == rel["source_id"],
            FindingRelationship.target_id == rel["target_id"],
            FindingRelationship.relationship_type == rel["relationship_type"]
        ).first()
        if not rel_existing:
            new_rel = FindingRelationship(
                source_id=rel["source_id"],
                target_id=rel["target_id"],
                relationship_type=rel["relationship_type"],
                metadata_=rel.get("metadata", {})
            )
            db.add(new_rel)

    # 3. Log Audit
    append_to_audit_log_db(db, AuditEntry(
        user=requested_by,
        action="THREAT_PACK_IMPORTED",
        module="THREAT",
        detail=f"Successfully imported threat pack '{pack_name}' version {version}."
    ))
    db.commit()
    
    return {
        "status": "success",
        "pack_name": pack_name,
        "version": version,
        "imported_findings": imported_findings_count
    }

def rollback_threat_pack(db: Session, pack_name: str, version: str, requested_by: str = "system") -> dict:
    source_tag = f"threat_pack:{pack_name}:{version}"
    
    # Find all finding IDs imported by this threat pack
    findings = db.query(Finding).filter(Finding.source == source_tag).all()
    finding_ids = [f.id for f in findings]
    
    if not finding_ids:
        return {"status": "skipped", "message": f"No active records found for threat pack '{pack_name}' version {version}."}
        
    # Delete relationships, sources, controls, and findings
    from sqlalchemy import or_
    db.query(FindingRelationship).filter(
        or_(FindingRelationship.source_id.in_(finding_ids), FindingRelationship.target_id.in_(finding_ids))
    ).delete(synchronize_session=False)
    
    db.query(FindingSource).filter(FindingSource.finding_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(FindingControl).filter(FindingControl.finding_id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.source == source_tag).delete(synchronize_session=False)
    
    append_to_audit_log_db(db, AuditEntry(
        user=requested_by,
        action="THREAT_PACK_ROLLED_BACK",
        module="THREAT",
        detail=f"Successfully rolled back threat pack '{pack_name}' version {version}."
    ))
    db.commit()
    
    return {
        "status": "success",
        "pack_name": pack_name,
        "version": version,
        "deleted_records": len(finding_ids)
    }
