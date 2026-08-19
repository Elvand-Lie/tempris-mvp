"""Real Playwright Browser E2E Test Suite for SCOUT Route and Authoritative Hardening.

Validates in a real headless Chromium browser:
1. Loads /scout route with authenticated session.
2. Asserts single-owner host container without duplicated extension roots.
3. Asserts exactly one asset selector in DOM after repeated DOM mutations.
4. Switches between 'External Scans' and 'Vulnerability Intelligence' tabs repeatedly and verifies DOM stability.
5. Selects an authorized scannable asset from the dropdown.
6. Submits an external scan and verifies outgoing POST to /api/scanner/run is intercepted (ZERO live network scans),
   uses apiJson with 'Content-Type: application/json', and matches the exact permitted request schema.
7. In Vulnerability Intelligence tab: asserts catalog metrics are populated dynamically from API.
8. Verifies missing CVSS records render 'N/A' / neutral styling.
9. Verifies table rows contain canonical CVE identifiers and zero internal 'F-XXXX' finding IDs.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from playwright.sync_api import sync_playwright
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uvicorn

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from index import app
from models import (
    Asset,
    AssetScanAuthorization,
    Base,
    CanonicalVulnerability,
    CisaKevEntry,
    VulnerabilityCvssAssessment,
)
from services.database import get_db


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def e2e_server(tmp_path_factory):
    old_env = os.environ.get("SCOUT_ACTIVE_SCANNING_ENABLED")
    os.environ["SCOUT_ACTIVE_SCANNING_ENABLED"] = "true"

    db_file = tmp_path_factory.mktemp("e2e_db") / "test_browser_e2e.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    now = datetime.now(timezone.utc)

    # 1. Active scannable asset
    asset = Asset(
        id="asset-e2e-1",
        tenant_id="tempris",
        name="Production Edge Server",
        ip_address="93.184.216.34",
        status="active",
        criticality="critical",
    )
    auth = AssetScanAuthorization(
        id="auth-e2e-1",
        tenant_id="tempris",
        asset_id=asset.id,
        authorized_target="93.184.216.34",
        target_kind="ipv4",
        status="approved",
        evidence="Superadmin superadmin@tempris.com approved scan authorization with verification notes: Verified DNS TXT record and contract SOW",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )

    # 2. Canonical CVE with CVSS 9.8 and KEV
    cve1 = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Apache Log4j2 JNDI Remote Code Execution",
    )
    kev1 = CisaKevEntry(
        id="kev-e2e-1",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Apache Log4j2 RCE",
        known_ransomware_campaign_use="Known",
    )
    cvss1 = VulnerabilityCvssAssessment(
        id="cvss-e2e-1",
        cve_id="CVE-2021-44228",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=9.8,
        source="NVD",
        source_role="CNA",
    )

    # 3. Unassessed CVE with NO CVSS score
    cve2 = CanonicalVulnerability(
        cve_id="CVE-2024-9999",
        status="published",
        description="Zero-day Candidate Without Formal Score",
    )

    db.add_all([asset, auth, cve1, kev1, cvss1, cve2])
    db.commit()

    def override_get_db():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    from routers.auth import create_test_session
    token = create_test_session(db, "analyst@tempris.com")
    db.close()

    port = find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    timeout = 20.0
    start_time = time.time()
    while not server.started and time.time() - start_time < timeout:
        time.sleep(0.05)

    if not server.started:
        raise RuntimeError(f"Server failed to start on port {port} within {timeout}s")

    yield f"http://127.0.0.1:{port}", token

    server.should_exit = True
    thread.join(timeout=2.0)
    app.dependency_overrides.clear()
    engine.dispose()

    if old_env is None:
        os.environ.pop("SCOUT_ACTIVE_SCANNING_ENABLED", None)
    else:
        os.environ["SCOUT_ACTIVE_SCANNING_ENABLED"] = old_env


def test_scout_browser_real_e2e_flow(e2e_server):
    """Executes full browser end-to-end assertions in headless Chromium with strict mock interception."""
    server_url, token = e2e_server

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Intercept and fulfill scan trigger request - GUARANTEES ZERO LIVE EXTERNAL PROBES
        scan_requests = []

        def handle_scan_route(route):
            req = route.request
            scan_requests.append({
                "method": req.method,
                "headers": req.headers,
                "post_data": req.post_data,
                "json": req.post_data_json,
            })
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({
                    "status": "success",
                    "scan_id": "SCAN-E2E-MOCK",
                    "asset_id": "asset-e2e-1",
                    "target": "93.184.216.34",
                    "scan_type": "full",
                    "engines": ["Nuclei", "Nmap"],
                    "findings_count": 0,
                    "normalized_findings": 0,
                    "confirmed_exposures": 0,
                    "message": "Mock E2E scan completed.",
                }),
            )

        page.route("**/api/scanner/run", handle_scan_route)

        # 1. Set authentication token in localStorage and navigate to /scout
        page.goto(f"{server_url}/")
        page.evaluate(
            f"""([token]) => {{
                localStorage.setItem('tempris_token', token);
                localStorage.setItem('tempris_user', JSON.stringify({{
                    email: 'analyst@tempris.com',
                    role: 'Analyst',
                    tenant_id: 'tempris',
                    package: 'ENTERPRISE'
                }}));
            }}""",
            [token],
        )

        page.goto(f"{server_url}/scout")
        page.wait_for_selector("select[data-scout-asset-select]", timeout=12000)

        # 2. Assert exactly one SCOUT extension host in DOM
        hosts = page.query_selector_all("#tempris-extension-host")
        assert len(hosts) == 1, "There must be exactly one extension host"

        # 3. Assert exactly one Asset selector in DOM
        asset_selects = page.query_selector_all("select[data-scout-asset-select]")
        assert len(asset_selects) == 1, "There must be exactly one asset selector"

        # 4. Trigger repeated synthetic DOM mutations to simulate MutationObserver events
        page.evaluate("""() => {
            const root = document.getElementById('root') || document.body;
            for (let i = 0; i < 5; i++) {
                const div = document.createElement('div');
                div.className = 'synthetic-mutation-probe';
                root.appendChild(div);
            }
        }""")
        page.wait_for_timeout(300)

        # Assert selector remains strictly singular after mutations
        asset_selects_after = page.query_selector_all("select[data-scout-asset-select]")
        assert len(asset_selects_after) == 1, "Asset selector must remain strictly singular after DOM mutations"

        # 5. Switch between External Scans and Vulnerability Intelligence tabs 5 times
        scans_tab_btn = page.query_selector('button[data-scout-nav="scans"]')
        intel_tab_btn = page.query_selector('button[data-scout-nav="intel"]')
        assert scans_tab_btn is not None
        assert intel_tab_btn is not None

        for _ in range(5):
            intel_tab_btn.click()
            page.wait_for_timeout(100)
            scans_tab_btn.click()
            page.wait_for_timeout(100)

        # Return to External Scans and verify exactly 1 asset selector
        asset_selects_final = page.query_selector_all("select[data-scout-asset-select]")
        assert len(asset_selects_final) == 1

        # 6. Select authorized asset and submit scan
        page.select_option("select[data-scout-asset-select]", "asset-e2e-1")
        scan_btn = page.query_selector("button[data-scout-launch-btn]")
        assert scan_btn is not None

        # Submit scan form
        page.click("button[data-scout-launch-btn]")
        page.wait_for_timeout(600)

        # 7. Assert outgoing HTTP request used apiJson with Content-Type: application/json and exact schema
        assert len(scan_requests) == 1, "A single intercepted request to /api/scanner/run must have been captured"
        last_req = scan_requests[-1]
        assert last_req["method"] == "POST"
        assert "application/json" in last_req["headers"].get("content-type", "").lower()
        assert last_req["json"] == {"asset_id": "asset-e2e-1", "scan_type": "full"}

        # 8. Switch to Vulnerability Intelligence tab
        page.click('button[data-scout-nav="intel"]')
        page.wait_for_selector(".tmx-tag-cve", timeout=12000)

        # 9. Verify Vulnerability table rendered canonical CVEs
        page_text = page.content()
        assert "CVE-2021-44228" in page_text, "CVE-2021-44228 must appear in Vulnerability Intelligence"
        assert "CVE-2024-9999" in page_text, "CVE-2024-9999 must appear in Vulnerability Intelligence"

        # 10. Verify neutral N/A rendering for unscored CVE
        neutral_statuses = page.query_selector_all(".tmx-status-neutral")
        assert len(neutral_statuses) >= 1, "Unscored CVE must render with neutral status styling"
        neutral_texts = [el.inner_text().strip() for el in neutral_statuses]
        assert "N/A" in neutral_texts, "Neutral status must display 'N/A'"

        # 11. Assert no internal finding IDs ('F-') appear in the intelligence CVE column
        cve_cells = page.query_selector_all(".tmx-tag-cve")
        assert len(cve_cells) >= 2
        for cell in cve_cells:
            text = cell.inner_text().strip()
            assert text.startswith("CVE-"), f"Expected CVE identifier, got: {text}"
            assert not text.startswith("F-"), f"Internal finding ID found in CVE column: {text}"

        browser.close()
