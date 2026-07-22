"""
Seed Findings â€” One-time import of vulnerability data into the database.

Reads KEV, PoC, and SSS JSON files and inserts findings into the findings table.
Idempotent: skips existing findings on re-run.

Usage:
    cd tempris/api
    python -m scripts.seed_findings
"""
import json
import os
import sys
import logging

# Ensure api/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.database import SessionLocal, init_db
from models import Finding
from services.tes_engine import calculate_sss_tes, priority_from_tes
from services.sss_contract import PUBLIC_SSS_FIELDS

logger = logging.getLogger("tempris.seed")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')


# â”€â”€ Scoring logic (ported from kev_loader.py) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

HIGH_RISK_VENDORS = ['Fortinet', 'Cisco', 'Ivanti', 'Palo Alto Networks', 'Citrix', 'SonicWall']

def _score_kev_vulnerability(vuln: dict) -> tuple[float, str, dict]:
    """Derive severity score from KEV fields when CVSS is not present."""
    vendor = vuln.get("vendorProject", "Unknown")
    ransomware_known = vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known"
    text = " ".join([
        vuln.get("vulnerabilityName", ""),
        vuln.get("shortDescription", ""),
        vuln.get("requiredAction", ""),
    ]).lower()

    if ransomware_known:
        cvss, bi, ac, ta = 9.8, 9.5, 8.0, 9.0
    elif any(t in text for t in ["remote code execution", "arbitrary code execution",
            "execute arbitrary code", "full system compromise", "authentication bypass",
            "unauthenticated", "sql injection", "command injection"]):
        cvss = 8.8 if vendor in HIGH_RISK_VENDORS else 8.2
        bi, ac, ta = 8.0, (8.0 if vendor in HIGH_RISK_VENDORS else 6.5), 6.5
    elif any(t in text for t in ["privilege escalation", "elevate privileges",
            "path traversal", "directory traversal", "deserialization",
            "server-side request forgery", "ssrf", "security feature bypass"]):
        cvss = 7.4 if vendor in HIGH_RISK_VENDORS else 7.0
        bi, ac, ta = 7.0, (7.0 if vendor in HIGH_RISK_VENDORS else 6.0), 5.5
    elif any(t in text for t in ["denial of service", "information disclosure",
            "cross-site scripting", "spoofing", "out-of-bounds read"]):
        cvss, bi, ac, ta = 6.4, 5.5, 6.0, 5.0
    else:
        cvss, bi, ac, ta = 6.8, 6.0, 6.0, 5.0

    priority = "P0" if cvss >= 9.0 else ("P1" if cvss >= 7.0 else "P2")
    raw_inputs = {
        "cvss": cvss, "exploitability": 10.0,
        "business_impact": bi, "asset_criticality": ac,
        "threat_actor_activity": ta,
    }
    return cvss, priority, raw_inputs


# â”€â”€ Asset mapping (simplified) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _build_vendor_asset_map(db) -> dict:
    """Build mapping from vendor/product keywords to asset IDs."""
    from models import Asset
    assets = db.query(Asset).filter(Asset.status == "active").all()
    asset_map = {}
    for asset in assets:
        keywords = set()
        for word in asset.name.lower().split():
            if len(word) > 2:
                keywords.add(word)
        if asset.tags:
            for tag in asset.tags:
                keywords.add(tag.lower())
        asset_map[asset.id] = {
            "name": asset.name, "criticality": asset.criticality,
            "ip_address": asset.ip_address, "keywords": keywords,
        }
    return asset_map


def _match_finding_to_asset(vendor: str, product: str, asset_map: dict) -> dict | None:
    """Match a finding to an internal asset using vendor+product keywords."""
    if not asset_map:
        return None
    vendor_lower = vendor.lower().strip()
    product_lower = product.lower().strip()
    best_match, best_score = None, 0

    for asset_id, info in asset_map.items():
        score = 0
        kw = info["keywords"]
        for w in vendor_lower.split():
            if len(w) > 2 and w in kw:
                score += 3
        for w in product_lower.split():
            if len(w) > 2 and w in kw:
                score += 2
        if vendor_lower in kw:
            score += 5
        if score > best_score:
            best_score = score
            best_match = {
                "asset_id": asset_id, "asset_name": info["name"],
                "asset_criticality": info["criticality"],
                "asset_ip": info["ip_address"], "match_score": score,
            }
    return best_match if best_score >= 3 else None


# â”€â”€ Seed functions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def seed_poc_findings(db, existing_ids: set) -> set:
    """Seed PoC scan findings from spectrum_findings.json."""
    path = os.path.join(DATA_DIR, 'spectrum_findings.json')
    if not os.path.exists(path):
        logger.info("No spectrum_findings.json found, skipping PoC.")
        return set()

    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    poc_cves = set()
    count = 0
    for idx, vuln in enumerate(data.get("findings", [])):
        fid = f"F-{2000 + idx}"
        if fid in existing_ids:
            continue
        cve_id = vuln.get('cve_id', 'Unknown')
        if cve_id != 'Unknown':
            poc_cves.add(cve_id)

        db.add(Finding(
            id=fid, cve=cve_id,
            title=vuln.get('name', 'Unknown'),
            vendor="Demo Target",
            product=vuln.get('template_id', 'Unknown'),
            cvss=vuln.get('cvss_score', 5.0),
            priority="P0",
            status="unmitigated",
            cisa_kev=vuln.get('kev_flagged', False),
            ransomware=vuln.get('ransomware_linked', False),
            date_added=vuln.get('scanned_at', ''),
            short_description=f"Host: {vuln.get('host', '')}",
            required_action="Investigate target asset",
            raw_inputs={
                "cvss": vuln.get('cvss_score', 5.0), "exploitability": 10.0,
                "business_impact": 9.5, "asset_criticality": 8.0,
                "threat_actor_activity": 9.0
            },
            source="poc",
        ))
        count += 1

    logger.info(f"Seeded {count} PoC findings.")
    return poc_cves


def seed_kev_findings(db, existing_ids: set, poc_cves: set, asset_map: dict):
    """Seed CISA KEV findings."""
    path = os.path.join(DATA_DIR, 'cisa_kev_2026_05_22.json')
    if not os.path.exists(path):
        logger.warning(f"KEV data file not found at {path}")
        return

    with open(path, 'r', encoding='utf-8') as f:
        kev_data = json.load(f)

    vulns = kev_data.get('vulnerabilities', [])
    vulns.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)

    count = 0
    mapped = 0
    for idx, vuln in enumerate(vulns):
        cve = vuln.get('cveID', 'Unknown')
        if cve in poc_cves:
            continue
        fid = f"F-{1000 + idx}" if idx < 1000 else f"F-1{idx:04d}"
        if fid in existing_ids:
            continue

        vendor = vuln.get('vendorProject', 'Unknown')
        product = vuln.get('product', 'Unknown')
        ransomware_known = vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known'
        cvss, priority, raw_inputs = _score_kev_vulnerability(vuln)

        asset_match = _match_finding_to_asset(vendor, product, asset_map)
        if asset_match:
            mapped += 1
            if asset_match["asset_criticality"] == "critical":
                cvss = min(10.0, cvss + 0.2)
                raw_inputs["cvss"] = cvss
                raw_inputs["asset_criticality"] = max(raw_inputs["asset_criticality"], 8.0)
                priority = "P0" if cvss >= 9.0 else ("P1" if cvss >= 7.0 else "P2")

        db.add(Finding(
            id=fid, cve=cve,
            title=vuln.get('vulnerabilityName', 'Unknown'),
            vendor=vendor, product=product,
            cvss=cvss, priority=priority,
            status="unmitigated",
            cisa_kev=True, ransomware=ransomware_known,
            date_added=vuln.get('dateAdded', ''),
            short_description=vuln.get('shortDescription', ''),
            required_action=vuln.get('requiredAction', ''),
            raw_inputs=raw_inputs,
            asset_id=asset_match["asset_id"] if asset_match else None,
            asset_data=asset_match,
            source="kev",
        ))
        count += 1

        # Commit in batches of 500
        if count % 500 == 0:
            db.commit()
            logger.info(f"  ... {count} KEV findings inserted")

    logger.info(f"Seeded {count} KEV findings. {mapped} mapped to internal assets.")


def seed_sss_findings(db, existing_ids: set):
    """Seed SSS supply chain findings."""
    path = os.path.join(DATA_DIR, 'sss_supply_chain_findings.json')
    if not os.path.exists(path):
        logger.info("No SSS supply chain findings file found, skipping.")
        return

    with open(path, 'r', encoding='utf-8') as f:
        sss_data = json.load(f)

    count = 0
    for idx, sf in enumerate(sss_data.get('findings', [])):
        fid = f"F-{3000 + idx}"
        if fid in existing_ids:
            continue

        scoring = sf.get('scoring', {})
        base_severity = scoring.get('base_severity', 7.0)
        tes_score = calculate_sss_tes(scoring)
        priority = priority_from_tes(tes_score)

        db.add(Finding(
            id=fid,
            finding_type=sf.get("type", "NON_CVE_SSS"),
            sub_class=sf.get("sub_class"),
            decision=sf.get("engine_decision"),
            cve=sf.get('finding_id', f'SSS-{idx}'),
            title=sf.get('title', 'Unknown'),
            vendor=sf.get('affected_ecosystem', 'Supply Chain'),
            product=', '.join(sf.get('attack_vectors', [])),
            cvss=base_severity,
            priority=priority,
            status="unmitigated",
            cisa_kev=False, ransomware=False,
            date_added=sf.get('ingested_at', ''),
            short_description=sf.get('description', ''),
            required_action=sf.get('recommended_action', 'Investigate'),
            raw_inputs={
                "cvss": base_severity, "exploitability": 10.0,
                "business_impact": tes_score,
                "asset_criticality": scoring.get('AGM', 1.0) * 7.0,
                "threat_actor_activity": scoring.get('TEF', 1.0) * 7.0,
            },
            sss_data={
                "type": sf.get('type'), "source": sf.get('source'),
                "scoring": scoring,
                "compensating_controls": sf.get('compensating_controls', []),
                "attack_vectors": sf.get('attack_vectors', []),
                "references": sf.get('references', []),
                "mas_trm_mapping": sf.get('mas_trm_mapping'),
            },
            source="sss",
        ))
        count += 1

    logger.info(f"Seeded {count} SSS supply chain findings.")


def _seed_threat_pack(db, existing_ids: set, filename: str, id_base: int, label: str):
    """Seed versioned threat-intel findings."""
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        logger.info(f"No {label} threat file found, skipping.")
        return

    with open(path, 'r', encoding='utf-8') as f:
        threat_data = json.load(f)

    existing_keys = set(existing_ids)
    existing_keys.update(r[0] for r in db.query(Finding.cve).filter(Finding.cve.isnot(None)).all())

    count = 0
    for idx, tf in enumerate(threat_data.get('findings', [])):
        fid = f"F-{id_base + idx}"
        finding_key = tf.get('finding_id', f'{label.upper()}-{idx}')
        if fid in existing_ids or finding_key in existing_keys:
            continue

        scoring = tf.get('scoring', {})
        base_severity = float(scoring.get('base_severity', 7.0) or 7.0)
        tes_score = calculate_sss_tes(scoring)
        priority = priority_from_tes(tes_score)

        finding_type = tf.get('type', 'NON_CVE_SSS')
        cisa_kev = tf.get('cisa_kev', finding_type == "CVE" and tf.get("source") == "CVE_KEV")
        source = "kev" if cisa_kev else ("cve" if finding_type == "CVE" else "sss")
        cvss = base_severity
        raw_inputs = {
            "cvss": cvss,
            "exploitability": 10.0,
            "business_impact": min(10.0, base_severity * float(scoring.get('DRF', 1.0) or 1.0)),
            "asset_criticality": min(10.0, 7.0 * float(scoring.get('TEF', 1.0) or 1.0)),
            "threat_actor_activity": min(10.0, 7.0 * float(scoring.get('AGM', 1.0) or 1.0)),
        }

        db.add(Finding(
            id=fid,
            finding_type=finding_type,
            sub_class=tf.get("sub_class"),
            decision=tf.get("engine_decision"),
            cve=finding_key,
            title=tf.get('title', 'Unknown'),
            vendor=tf.get('affected_ecosystem', 'Threat Intel'),
            product=', '.join(tf.get('attack_vectors', [])),
            cvss=cvss,
            priority=priority,
            status="unmitigated",
            cisa_kev=cisa_kev,
            ransomware=tf.get('ransomware', False),
            date_added=tf.get('ingested_at', ''),
            short_description=tf.get('description', ''),
            required_action=tf.get('recommended_action', 'Investigate'),
            raw_inputs=raw_inputs,
            sss_data={
                "type": finding_type,
                "sub_class": tf.get("sub_class"),
                "source": tf.get('source'),
                "scoring": scoring,
                "compensating_controls": tf.get('compensating_controls', []),
                "attack_vectors": tf.get('attack_vectors', []),
                "references": tf.get('references', []),
                "fim_bypass": tf.get('fim_bypass', False),
                "fim_bypass_note": tf.get('fim_bypass_note'),
                "mitre_technique": tf.get('mitre_technique'),
                "cwe": tf.get('cwe'),
                "kev_date_added": tf.get('kev_date_added'),
                "patch_version": tf.get('patch_version'),
                "patch_date": tf.get('patch_date'),
                "affected_versions": tf.get('affected_versions'),
                "nc4_alert": tf.get('nc4_alert'),
                "epss_percentile": tf.get('epss_percentile'),
                "source_verification": tf.get('source_verification'),
                "mas_trm_mapping": tf.get('mas_trm_mapping'),
                "patch_available": tf.get('patch_available'),
                "engine_decision": tf.get("engine_decision"),
                **{
                    key: tf[key]
                    for key in PUBLIC_SSS_FIELDS
                    if tf.get(key) not in (None, "", [])
                },
            },
            source=source,
        ))
        existing_keys.add(finding_key)
        count += 1

    logger.info(f"Seeded {count} {label} threat findings.")

def seed_v50_threats(db, existing_ids: set):
    """Seed v50 new threat findings (pedit COW, Signal, Node.js, AI eval)."""
    _seed_threat_pack(db, existing_ids, 'v50_new_threats.json', 4000, 'v50')


def seed_v51_threats(db, existing_ids: set):
    """Seed v51 new threat findings."""
    _seed_threat_pack(db, existing_ids, 'v51_new_threats.json', 5000, 'v51')


def seed_v51_brief_findings(db, existing_ids: set):
    """Seed normalized findings from the v51 developer briefs."""
    _seed_threat_pack(db, existing_ids, 'v51_brief_findings.json', 6000, 'v51 brief')


def seed_v54_final_findings(db, existing_ids: set):
    """Seed normalized findings from the v54 final update notes."""
    _seed_threat_pack(db, existing_ids, 'v54_final_update_findings.json', 7000, 'v54 final')


def seed_v62_debrief_findings(db, existing_ids: set):
    """Seed server-authoritative decision records from the v62 debrief."""
    _seed_threat_pack(db, existing_ids, 'v62_debrief_findings.json', 8000, 'v62 debrief')


def seed_all():
    """Run all seed operations."""
    init_db()
    db = SessionLocal()
    try:
        # Get existing finding IDs for idempotency
        existing_ids = set(r[0] for r in db.query(Finding.id).all())
        if existing_ids:
            logger.info(f"Found {len(existing_ids)} existing findings, skipping duplicates.")

        # Build asset map for KEV matching
        asset_map = _build_vendor_asset_map(db)
        logger.info(f"Built asset map with {len(asset_map)} assets.")

        # Seed in order: PoC â†’ KEV â†’ SSS â†’ versioned threat packs
        poc_cves = seed_poc_findings(db, existing_ids)
        db.commit()

        seed_kev_findings(db, existing_ids, poc_cves, asset_map)
        db.commit()

        seed_sss_findings(db, existing_ids)
        db.commit()

        seed_v50_threats(db, existing_ids)
        db.commit()

        seed_v51_threats(db, existing_ids)
        db.commit()

        seed_v51_brief_findings(db, existing_ids)
        db.commit()

        seed_v54_final_findings(db, existing_ids)
        db.commit()

        seed_v62_debrief_findings(db, existing_ids)
        db.commit()

        # Final count
        total = db.query(Finding).count()
        logger.info(f"Seeding complete. Total findings in DB: {total}")

    except Exception as e:
        db.rollback()
        logger.error(f"Seeding failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_all()

