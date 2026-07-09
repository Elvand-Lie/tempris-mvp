"""
Tempris Wave 1 Phase 1 — TACF Audit Trail Seeder
Generates realistic audit events for the demo database.
Demonstrates MAS TRM-compliant append-only logging.

Usage:
    python3 tempris_poc_tacf_seed.py

Output:
    tacf_audit_log.json   — importable into PostgreSQL or any DB
    tacf_audit_log.csv    — viewable in Excel
"""

import json, csv, uuid, datetime, random

EVENT_TYPES = [
    ("USER_LOGIN",            "admin@tempris.sg",    "Auth service",      "User authenticated successfully"),
    ("ASSET_CREATED",         "admin@tempris.sg",    "SYNTHESIS",         "Asset registered in inventory"),
    ("SCOUT_SCAN_STARTED",    "analyst@tempris.sg",  "SCOUT module",      "Nuclei scan initiated against target"),
    ("SCOUT_SCAN_COMPLETED",  "system",              "SCOUT module",      "Scan completed, findings published to SPECTRUM"),
    ("CVE_FINDING_CREATED",   "system",              "SPECTRUM engine",   "TES scoring applied to new CVE finding"),
    ("EDIP_DECISION_MADE",    "analyst@tempris.sg",  "SPECTRUM EDIP",     "Analyst decision recorded: Mitigate"),
    ("EDIP_DECISION_MADE",    "analyst@tempris.sg",  "SPECTRUM EDIP",     "Analyst decision recorded: Accept"),
    ("EDIP_DECISION_MADE",    "ciso@tempris.sg",     "SPECTRUM EDIP",     "CISO override: Transfer to insurance"),
    ("COMPLIANCE_CTRL_UPDATE","admin@tempris.sg",    "STANDARD module",   "MAS TRM control status updated to Compliant"),
    ("COMPLIANCE_CTRL_UPDATE","analyst@tempris.sg",  "STANDARD module",   "NIST CSF control marked Partial"),
    ("EVIDENCE_UPLOADED",     "analyst@tempris.sg",  "STANDARD module",   "Evidence document attached to control"),
    ("AI_NARRATIVE_GEN",      "system",              "SPOTLIGHT Claude",  "Board report narrative generated via Claude API"),
    ("REPORT_EXPORTED",       "ciso@tempris.sg",     "SPOTLIGHT module",  "PDF board report exported and logged"),
    ("SPEAK_QUERY",           "analyst@tempris.sg",  "SPEAK chatbot",     "AI security query processed"),
    ("USER_LOGIN",            "viewer@tempris.sg",   "Auth service",      "Read-only user authenticated"),
    ("USER_LOGOUT",           "analyst@tempris.sg",  "Auth service",      "Session ended"),
    ("STRIKE_AUTH_CREATED",   "ciso@tempris.sg",     "STRIKE module",     "Written scope authorisation created"),
    ("STRIKE_SIM_STARTED",    "analyst@tempris.sg",  "STRIKE module",     "Red team simulation initiated"),
    ("STRIKE_SIM_COMPLETED",  "system",              "STRIKE module",     "Simulation completed, results linked to SPECTRUM"),
    ("MAS_NOTIFICATION_PREP", "ciso@tempris.sg",     "STANDARD module",   "MAS 1-hour notification draft prepared"),
]

CVE_SAMPLES = [
    "CVE-2024-53704", "CVE-2024-3400", "CVE-2021-44228",
    "CVE-2024-47575", "CVE-2023-46604", "CVE-2024-1708",
]

DECISIONS = ["Mitigate", "Accept", "Transfer", "Ignore"]
IPS       = [f"10.0.1.{i}" for i in range(2, 20)]

def make_event(idx, base_time):
    event_type, actor, source, description = random.choice(EVENT_TYPES)
    ts = base_time + datetime.timedelta(
        hours=random.randint(0, 167),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    meta = {
        "session_id": str(uuid.uuid4()),
        "ip_address":  random.choice(IPS),
    }
    if "CVE" in event_type or "FINDING" in event_type:
        meta["cve_id"]    = random.choice(CVE_SAMPLES)
        meta["tes_score"] = round(random.uniform(5.5, 9.8), 2)
    if "EDIP" in event_type:
        meta["decision"]  = random.choice(DECISIONS)
        meta["cve_id"]    = random.choice(CVE_SAMPLES)
        meta["tes_score"] = round(random.uniform(5.5, 9.8), 2)
    if "REPORT" in event_type or "NARRATIVE" in event_type:
        meta["report_id"] = str(uuid.uuid4())[:8].upper()

    return {
        "id":           str(uuid.uuid4()),
        "sequence_num": idx + 1,
        "timestamp":    ts.isoformat() + "Z",
        "event_type":   event_type,
        "actor":        actor,
        "source_module":source,
        "description":  description,
        "metadata":     meta,
        "immutable":    True,
        "hash":         str(uuid.uuid4()).replace("-","")[:32],
    }

# Generate 75 events over last 30 days
base  = datetime.datetime.utcnow() - datetime.timedelta(days=30)
events = [make_event(i, base) for i in range(75)]
events.sort(key=lambda x: x["timestamp"])

# Reassign sequence numbers after sort
for i, e in enumerate(events):
    e["sequence_num"] = i + 1

# Save JSON
with open("tacf_audit_log.json", "w") as f:
    json.dump({
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "description":  "Tempris TACF append-only audit trail — MAS TRM compliant",
        "total_events": len(events),
        "events":       events
    }, f, indent=2)

# Save CSV (for Excel viewing)
with open("tacf_audit_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "sequence_num","timestamp","event_type","actor",
        "source_module","description","cve_id","tes_score",
        "decision","session_id","ip_address","immutable"
    ])
    for e in events:
        m = e["metadata"]
        writer.writerow([
            e["sequence_num"], e["timestamp"], e["event_type"],
            e["actor"], e["source_module"], e["description"],
            m.get("cve_id",""), m.get("tes_score",""),
            m.get("decision",""), m.get("session_id",""),
            m.get("ip_address",""), e["immutable"]
        ])

# Summary
print(f"\n{'='*60}")
print(f"  TACF Audit Trail — {len(events)} events generated")
print(f"{'='*60}")

counts = {}
for e in events:
    counts[e["event_type"]] = counts.get(e["event_type"], 0) + 1
for ev_type, count in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {count:>3}x  {ev_type}")

print(f"\n  Saved → tacf_audit_log.json")
print(f"  Saved → tacf_audit_log.csv  (open in Excel)")
print(f"\n  Demo tip: Filter CSV by event_type = EDIP_DECISION_MADE")
print(f"  Show the CISO: every analyst decision permanently recorded.")
print("="*60)
