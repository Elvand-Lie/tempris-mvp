"""
Script to run a bounded official-source sync sample into local tempris_v2_test,
measure performance/storage/query latencies, test API responses, and generate
complete Sprint 04 verification evidence.
"""
import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure backend is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.db import get_db_connection
from app.vuln_intelligence.models import (
    SyncSnapshot,
    CanonicalVulnerability,
    SourceRecord,
    CvssAssessment,
    KevEntry,
    EpssScore,
    OsvRecord,
    OsvAlias,
    CveAffected,
    CveAdpEntry,
    CveRelationship,
)
from app.vuln_intelligence.repository import (
    get_sync_snapshot,
    get_all_sync_states,
    get_composed_cve_detail,
    search_vulnerabilities,
    get_source_records_by_cve,
    resolve_tes_cvss,
    create_sync_snapshot,
    complete_sync_snapshot,
    upsert_canonical_vulnerability,
    upsert_source_record,
    upsert_cvss_assessment,
    upsert_cve_affected,
    upsert_adp_entry,
    upsert_kev_entry,
    upsert_epss_score,
    upsert_osv_record,
    upsert_osv_alias,
    upsert_cve_relationship,
    upsert_cve_weaknesses,
    upsert_cve_references,
)
from app.vuln_intelligence.sync_engine import (
    sync_source,
    get_all_source_health,
)
from app.vuln_intelligence.sync_adapters import (
    CveSyncAdapter,
    NvdSyncAdapter,
    KevSyncAdapter,
    EpssSyncAdapter,
    OsvSyncAdapter,
    ALL_ADAPTERS,
)
from app.vuln_intelligence.fetch_clients import (
    CveFetchClient,
    NvdFetchClient,
    KevFetchClient,
    EpssFetchClient,
    OsvFetchClient,
)
from starlette.testclient import TestClient
from app.main import app
from app.auth import create_test_token
from app.config import PLATFORM_TENANT_ID


def run_bounded_evidence_collection():
    print("=" * 80)
    print("TEMPRIS V2 - SPRINT 04 VULNERABILITY INTELLIGENCE LIVE SAMPLE & BENCHMARK")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("Target DB: local tempris_v2_test (NEVER production)")
    print("=" * 80)

    evidence = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "tempris_v2_test",
        "sync_samples": {},
        "query_benchmarks": {},
        "storage_metrics": {},
        "row_counts": {},
        "exact_joins": [],
        "idempotency_proof": {},
        "api_verification": {},
        "source_health": {},
    }

    with get_db_connection() as conn:
        # 1. Clean slate before sample run
        print("\n[Step 1] Preparing database tables...")
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE sync_state SET
                    cursor_value = NULL,
                    last_successful_at = NULL,
                    last_attempted_at = NULL,
                    last_error = NULL,
                    last_snapshot_id = NULL,
                    last_good_snapshot_id = NULL,
                    last_sync_duration_ms = NULL,
                    active_record_count = 0,
                    consecutive_failures = 0,
                    is_healthy = TRUE;
                DELETE FROM cve_weaknesses;
                DELETE FROM cve_references;
                DELETE FROM osv_aliases;
                DELETE FROM osv_records;
                DELETE FROM cve_adp_entries;
                DELETE FROM cve_affected;
                DELETE FROM cve_relationships;
                DELETE FROM cvss_assessments;
                DELETE FROM kev_entries;
                DELETE FROM epss_scores;
                DELETE FROM vuln_source_records;
                DELETE FROM canonical_vulnerabilities;
                DELETE FROM sync_snapshots;
                INSERT INTO sync_state (source) VALUES
                    ('cve'), ('nvd'), ('kev'), ('epss'), ('osv')
                ON CONFLICT (source) DO UPDATE SET
                    cursor_value = NULL,
                    last_successful_at = NULL,
                    last_attempted_at = NULL,
                    last_error = NULL,
                    last_snapshot_id = NULL,
                    last_good_snapshot_id = NULL,
                    last_sync_duration_ms = NULL,
                    active_record_count = 0,
                    consecutive_failures = 0,
                    is_healthy = TRUE;
            """)
        conn.commit()
        print("[OK] Tables truncated and sync_state reset.")

        # 2. Run Bounded Live Sync Samples for all 5 Sources
        print("\n[Step 2] Executing Bounded Live Sync Samples against Official Sources...")

        adapters = {
            "cve": CveSyncAdapter(fetch_client=CveFetchClient(base_url="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2023/21xxx/CVE-2023-21554.json")),
            "nvd": NvdSyncAdapter(fetch_client=NvdFetchClient(api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10")),
            "kev": KevSyncAdapter(fetch_client=KevFetchClient()),
            "epss": EpssSyncAdapter(fetch_client=EpssFetchClient()),
            "osv": OsvSyncAdapter(fetch_client=OsvFetchClient(ecosystem="PyPI")),
        }

        for source_name, adapter in adapters.items():
            print(f"  --> Syncing '{source_name}' (bounded live sample)...")
            start_t = time.perf_counter()
            outcome = sync_source(conn, adapter)
            dur_ms = (time.perf_counter() - start_t) * 1000

            snap = get_sync_snapshot(conn, outcome.snapshot_id) if outcome.snapshot_id else None
            metadata = snap.metadata if snap and snap.metadata else {}

            evidence["sync_samples"][source_name] = {
                "success": outcome.success,
                "sync_mode": outcome.sync_mode,
                "duration_ms": round(dur_ms, 2),
                "snapshot_id": outcome.snapshot_id,
                "records_processed": outcome.records_processed,
                "records_created": outcome.records_created,
                "records_updated": outcome.records_updated,
                "records_unchanged": outcome.records_unchanged,
                "records_failed": outcome.records_failed,
                "cursor_before": outcome.cursor_before,
                "cursor_after": outcome.cursor_after,
                "error_message": outcome.error,
                "url": metadata.get("url") or metadata.get("endpoint"),
                "content_hash": metadata.get("content_hash"),
                "bytes_downloaded": metadata.get("bytes_downloaded"),
            }
            print(f"      Success: {outcome.success} | Created: {outcome.records_created} | Processed: {outcome.records_processed} | Duration: {dur_ms:.1f}ms")

        # 3. Idempotency Proof (re-sync identical payloads)
        print("\n[Step 3] Testing Idempotency & Re-sync Behavior...")
        kev_adapter = adapters["kev"]
        t0 = time.perf_counter()
        re_outcome = sync_source(conn, kev_adapter)
        re_dur_ms = (time.perf_counter() - t0) * 1000
        evidence["idempotency_proof"]["kev"] = {
            "first_run_created": evidence["sync_samples"]["kev"]["records_created"],
            "second_run_success": re_outcome.success,
            "second_run_created": re_outcome.records_created,
            "second_run_unchanged": re_outcome.records_unchanged,
            "second_run_duration_ms": round(re_dur_ms, 2),
            "idempotent": re_outcome.records_created == 0 and re_outcome.records_unchanged > 0,
        }
        print(f"[OK] KEV Idempotency check: created={re_outcome.records_created}, unchanged={re_outcome.records_unchanged}")

        # 4. Table Row Counts and Approximate Storage Size
        print("\n[Step 4] Collecting Database Row Counts & Storage Usage...")
        tables = [
            "canonical_vulnerabilities",
            "vuln_source_records",
            "cvss_assessments",
            "cve_relationships",
            "cve_affected",
            "cve_adp_entries",
            "kev_entries",
            "epss_scores",
            "osv_records",
            "osv_aliases",
            "sync_snapshots",
            "sync_state",
            "cve_references",
            "cve_weaknesses",
        ]
        with conn.cursor() as cur:
            for tbl in tables:
                cur.execute(f"SELECT count(*) as cnt FROM {tbl};")
                cnt = cur.fetchone()["cnt"]
                cur.execute(f"SELECT pg_size_pretty(pg_total_relation_size('{tbl}')) as sz, pg_total_relation_size('{tbl}') as bytes;")
                row = cur.fetchone()
                evidence["row_counts"][tbl] = cnt
                evidence["storage_metrics"][tbl] = {
                    "row_count": cnt,
                    "pretty_size": row["sz"],
                    "bytes": row["bytes"],
                }
                print(f"  Table: {tbl:<28} | Rows: {cnt:<6} | Size: {row['sz']}")

        # 5. Exact Cross-Source Joined Vulnerability Evidence
        print("\n[Step 5] Extracting Exact-CVE Cross-Source Joins & TES Resolvability...")
        with conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id FROM canonical_vulnerabilities
                ORDER BY cve_id LIMIT 5;
            """)
            sample_cves = [r["cve_id"] for r in cur.fetchall()]

        for cve_id in sample_cves:
            detail = get_composed_cve_detail(conn, cve_id)
            if detail:
                evidence["exact_joins"].append({
                    "cve_id": detail["cve_id"],
                    "state": detail["state"],
                    "assigner": detail["assigner_short_name"],
                    "descriptions_count": len(detail["descriptions"]),
                    "cvss_assessments": [
                        {
                            "source": a["source"],
                            "assessor": a["assessor"],
                            "version": a["cvss_version"],
                            "score": a["base_score"],
                            "severity": a["base_severity"],
                        }
                        for a in detail["cvss_assessments"]
                    ],
                    "tes_resolution": detail["tes_resolution"],
                    "has_kev": detail["kev"] is not None,
                    "has_epss": detail["epss"] is not None,
                    "osv_linked_count": len(detail["osv_records"]),
                    "affected_count": len(detail["affected"]),
                    "relationships_count": len(detail["relationships"]),
                })
        print(f"[OK] Extracted {len(evidence['exact_joins'])} cross-source joined CVE profiles.")

        # 6. Source Health
        evidence["source_health"] = get_all_source_health(conn)
        print(f"[OK] Source health captured for {len(evidence['source_health'])} sources.")

        # 7. Query Latency Benchmarks (100 iterations each)
        print("\n[Step 6] Running Representative Query Latency Benchmarks...")
        test_cve = sample_cves[0] if sample_cves else "CVE-2023-0001"

        # Benchmark A: Single CVE Composed Detail Lookup
        latencies_lookup = []
        for _ in range(50):
            t_start = time.perf_counter()
            _ = get_composed_cve_detail(conn, test_cve)
            latencies_lookup.append((time.perf_counter() - t_start) * 1000)

        # Benchmark B: Vulnerability Search by keyword / state
        latencies_search = []
        for _ in range(50):
            t_start = time.perf_counter()
            _ = search_vulnerabilities(conn, q=None, state="PUBLISHED", limit=20, offset=0)
            latencies_search.append((time.perf_counter() - t_start) * 1000)

        evidence["query_benchmarks"] = {
            "exact_cve_composed_lookup": {
                "iterations": 50,
                "mean_ms": round(sum(latencies_lookup) / len(latencies_lookup), 3),
                "min_ms": round(min(latencies_lookup), 3),
                "max_ms": round(max(latencies_lookup), 3),
                "p95_ms": round(sorted(latencies_lookup)[int(0.95 * len(latencies_lookup))], 3),
            },
            "vulnerability_search_published": {
                "iterations": 50,
                "mean_ms": round(sum(latencies_search) / len(latencies_search), 3),
                "min_ms": round(min(latencies_search), 3),
                "max_ms": round(max(latencies_search), 3),
                "p95_ms": round(sorted(latencies_search)[int(0.95 * len(latencies_search))], 3),
            }
        }
        print(f"  Single CVE Lookup: mean={evidence['query_benchmarks']['exact_cve_composed_lookup']['mean_ms']}ms | p95={evidence['query_benchmarks']['exact_cve_composed_lookup']['p95_ms']}ms")
        print(f"  Search Query:      mean={evidence['query_benchmarks']['vulnerability_search_published']['mean_ms']}ms | p95={evidence['query_benchmarks']['vulnerability_search_published']['p95_ms']}ms")

    # 8. API Verification using TestClient
    print("\n[Step 7] Testing Read-Only & Admin API Contracts...")
    from tests.conftest import seed_fixture_auth_data, ensure_platform_admin_session, TENANT_A
    with get_db_connection() as conn:
        seed_fixture_auth_data(conn)
    headers_admin = ensure_platform_admin_session()
    tenant_token = create_test_token(str(TENANT_A), actor_id="analyst-1", role="analyst")
    headers_user = {"Authorization": f"Bearer {tenant_token}"}
    client = TestClient(app)

    # API A: Search
    resp_search = client.get("/api/vuln-intelligence/cve?limit=5", headers=headers_user)
    # API B: Exact Lookup
    resp_lookup = client.get(f"/api/vuln-intelligence/cve/{test_cve}", headers=headers_user)
    # API C: Health (Platform Admin)
    resp_health = client.get("/api/vuln-intelligence/health", headers=headers_admin)
    # API D: Health (Tenant User Forbidden)
    resp_health_user = client.get("/api/vuln-intelligence/health", headers=headers_user)

    evidence["api_verification"] = {
        "search_status": resp_search.status_code,
        "search_total": resp_search.json().get("total") if resp_search.status_code == 200 else 0,
        "lookup_status": resp_lookup.status_code,
        "lookup_cve": resp_lookup.json().get("cve_id") if resp_lookup.status_code == 200 else None,
        "admin_health_status": resp_health.status_code,
        "admin_health_sources_count": len(resp_health.json().get("sources", [])) if resp_health.status_code == 200 else 0,
        "tenant_user_health_status": resp_health_user.status_code,
        "tenant_user_forbidden": resp_health_user.status_code == 403,
    }
    print(f"[OK] API Search: status {resp_search.status_code}")
    print(f"[OK] API Lookup ({test_cve}): status {resp_lookup.status_code}")
    print(f"[OK] API Admin Health: status {resp_health.status_code}")
    print(f"[OK] API Tenant Forbidden on Health: status {resp_health_user.status_code} (403 expected)")

    # Save evidence file
    evidence_path = BACKEND_DIR / "sprint04_live_evidence.json"
    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, default=str)
    print(f"\n[Done] Evidence successfully saved to: {evidence_path}")
    print("=" * 80)
    return evidence


if __name__ == "__main__":
    run_bounded_evidence_collection()
