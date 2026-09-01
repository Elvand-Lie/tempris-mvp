# backend/tests/test_vuln_fetch_clients.py
"""
Unit and contract tests for official-source fetch clients:
  1. CveFetchClient (cvelistV5)
  2. NvdFetchClient (NVD 2.0 API)
  3. KevFetchClient (CISA KEV catalog)
  4. EpssFetchClient (FIRST EPSS bulk)
  5. OsvFetchClient (OSV GCS / API)

All tests use offline mock transports — 100% deterministic, zero network calls.
"""
import gzip
import io
import json
import zipfile
import pytest
import httpx

from app.vuln_intelligence.fetch_clients import (
    CveFetchClient,
    NvdFetchClient,
    KevFetchClient,
    EpssFetchClient,
    OsvFetchClient,
)


class TestCveFetchClient:
    """Offline tests for CVE / cvelistV5 fetch client."""

    def test_fetch_bootstrap_from_zip(self):
        # Create a mock zip in memory with two CVE records
        cve_record_1 = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2023-1001", "state": "PUBLISHED"},
            "containers": {"cna": {"title": "Test 1"}},
        }
        cve_record_2 = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2023-1002", "state": "PUBLISHED"},
            "containers": {"cna": {"title": "Test 2"}},
        }

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            z.writestr("cves/2023/1xxx/CVE-2023-1001.json", json.dumps(cve_record_1))
            z.writestr("cves/2023/1xxx/CVE-2023-1002.json", json.dumps(cve_record_2))
            z.writestr("README.md", "# cvelistV5")

        zip_bytes = zip_buf.getvalue()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=zip_bytes, headers={"Content-Type": "application/zip"})

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)

        fetcher = CveFetchClient(client=client)
        result = fetcher.fetch(cursor=None, batch_size=10)

        assert result.error is None
        assert result.is_bootstrap is True
        assert len(result.records) == 2
        assert result.cursor_after is not None
        assert result.records[0]["cveMetadata"]["cveId"] == "CVE-2023-1001"

    def test_fetch_bootstrap_respects_batch_size(self):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            for i in range(5):
                rec = {
                    "dataType": "CVE_RECORD",
                    "dataVersion": "5.1",
                    "cveMetadata": {"cveId": f"CVE-2023-{1000 + i}", "state": "PUBLISHED"},
                }
                z.writestr(f"cves/2023/{i}xxx/CVE-2023-{1000 + i}.json", json.dumps(rec))

        transport = httpx.MockTransport(lambda req: httpx.Response(200, content=zip_buf.getvalue()))
        client = httpx.Client(transport=transport)

        fetcher = CveFetchClient(client=client)
        result = fetcher.fetch(cursor=None, batch_size=2)

        assert len(result.records) == 2

    def test_fetch_http_error_handled(self):
        transport = httpx.MockTransport(lambda req: httpx.Response(500, text="Internal Error"))
        client = httpx.Client(transport=transport)

        fetcher = CveFetchClient(client=client)
        result = fetcher.fetch(cursor=None)

        assert result.error is not None
        assert "HTTP 500" in result.error
        assert len(result.records) == 0


class TestNvdFetchClient:
    """Offline tests for NVD 2.0 API fetch client."""

    def test_fetch_bootstrap_success(self):
        nvd_payload = {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-09-01T12:00:00.000",
            "vulnerabilities": [
                {"cve": {"id": "CVE-2023-2001", "sourceIdentifier": "cve@mitre.org"}},
                {"cve": {"id": "CVE-2023-2002", "sourceIdentifier": "cve@mitre.org"}},
            ],
        }

        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, json=nvd_payload)

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)

        fetcher = NvdFetchClient(client=client, api_key="test-api-key-12345")
        result = fetcher.fetch(cursor=None, batch_size=10)

        assert result.error is None
        assert result.is_bootstrap is True
        assert len(result.records) == 2
        assert result.cursor_after == "2026-09-01T12:00:00.000"
        assert result.metadata["totalResults"] == 2

        # Verify auth header and parameters
        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert req.headers["apiKey"] == "test-api-key-12345"
        assert "resultsPerPage=10" in str(req.url)

    def test_fetch_incremental_sets_last_mod_params(self):
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, json={
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "timestamp": "2026-09-01T15:00:00.000",
                "vulnerabilities": [{"cve": {"id": "CVE-2023-2001"}}],
            })

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)

        fetcher = NvdFetchClient(client=client)
        result = fetcher.fetch(cursor="2026-08-15T00:00:00.000Z")

        assert result.is_bootstrap is False
        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert "lastModStartDate=" in str(req.url)

    def test_fetch_rate_limit_retry(self):
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, text="Rate Limit Exceeded")
            return httpx.Response(200, json={
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "timestamp": "2026-09-01T12:00:00.000",
                "vulnerabilities": [{"cve": {"id": "CVE-2023-2001"}}],
            })

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)

        fetcher = NvdFetchClient(client=client, api_key="key")
        result = fetcher.fetch(cursor=None)

        assert attempts == 2
        assert result.error is None
        assert len(result.records) == 1


class TestKevFetchClient:
    """Offline tests for CISA KEV catalog fetch client."""

    def test_fetch_kev_catalog(self):
        kev_payload = {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2026.09.01",
            "dateReleased": "2026-09-01T08:00:00.000Z",
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2023-3001",
                    "vendorProject": "TestVendor",
                    "product": "TestProd",
                    "vulnerabilityName": "Vuln 1",
                    "dateAdded": "2023-01-15",
                    "shortDescription": "Test desc",
                    "requiredAction": "Apply patch",
                    "dueDate": "2023-02-15",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "None",
                },
                {
                    "cveID": "CVE-2023-3002",
                    "vendorProject": "Vendor2",
                    "product": "Prod2",
                    "vulnerabilityName": "Vuln 2",
                    "dateAdded": "2023-01-20",
                    "shortDescription": "Desc 2",
                    "requiredAction": "Apply update",
                    "dueDate": "2023-02-20",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                },
            ],
        }

        transport = httpx.MockTransport(lambda req: httpx.Response(200, json=kev_payload))
        client = httpx.Client(transport=transport)

        fetcher = KevFetchClient(client=client)
        result = fetcher.fetch(cursor=None, batch_size=10)

        assert result.error is None
        assert result.is_bootstrap is True
        assert len(result.records) == 2
        assert result.records[0]["cveID"] == "CVE-2023-3001"
        assert result.cursor_after == "2026-09-01T08:00:00.000Z"
        assert result.metadata["catalogVersion"] == "2026.09.01"


class TestEpssFetchClient:
    """Offline tests for FIRST EPSS bulk CSV fetch client."""

    def test_fetch_epss_gzipped_csv(self):
        raw_csv = (
            "#model_version:v2023.03.01,score_date:2026-09-01T00:00:00+0000\n"
            "cve,epss,percentile\n"
            "CVE-2023-4001,0.01234,0.45678\n"
            "CVE-2023-4002,0.98765,0.99999\n"
        )
        compressed = gzip.compress(raw_csv.encode("utf-8"))

        transport = httpx.MockTransport(lambda req: httpx.Response(200, content=compressed))
        client = httpx.Client(transport=transport)

        fetcher = EpssFetchClient(client=client)
        result = fetcher.fetch(cursor=None)

        assert result.error is None
        assert result.is_bootstrap is True
        assert len(result.records) == 1
        assert "CVE-2023-4001,0.01234,0.45678" in result.records[0]
        assert result.cursor_after == "2026-09-01T00:00:00+0000"
        assert result.metadata["model_version"] == "v2023.03.01"

    def test_fetch_epss_plain_csv_fallback(self):
        raw_csv = (
            "#model_version:v2023.03.01,score_date:2026-09-01\n"
            "cve,epss,percentile\n"
            "CVE-2023-4001,0.05000,0.60000\n"
        )

        transport = httpx.MockTransport(lambda req: httpx.Response(200, text=raw_csv))
        client = httpx.Client(transport=transport)

        fetcher = EpssFetchClient(client=client)
        result = fetcher.fetch(cursor=None)

        assert result.error is None
        assert len(result.records) == 1
        assert "CVE-2023-4001" in result.records[0]


class TestOsvFetchClient:
    """Offline tests for OSV ecosystem fetch client."""

    def test_fetch_osv_from_zip(self):
        osv_rec_1 = {
            "schema_version": "1.6.0",
            "id": "GHSA-1111-2222-3333",
            "summary": "Vulnerability in npm package foo",
            "modified": "2026-09-01T00:00:00Z",
            "published": "2026-08-01T00:00:00Z",
            "aliases": ["CVE-2023-5001"],
            "package": {"name": "foo", "ecosystem": "npm"},
        }
        osv_rec_2 = {
            "schema_version": "1.6.0",
            "id": "GHSA-4444-5555-6666",
            "summary": "Vulnerability in npm package bar",
            "modified": "2026-09-01T00:00:00Z",
            "published": "2026-08-01T00:00:00Z",
            "aliases": ["CVE-2023-5002"],
            "package": {"name": "bar", "ecosystem": "npm"},
        }

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            z.writestr("GHSA-1111-2222-3333.json", json.dumps(osv_rec_1))
            z.writestr("GHSA-4444-5555-6666.json", json.dumps(osv_rec_2))

        transport = httpx.MockTransport(lambda req: httpx.Response(200, content=zip_buf.getvalue(), headers={"Content-Type": "application/zip"}))
        client = httpx.Client(transport=transport)

        fetcher = OsvFetchClient(ecosystem="npm", client=client)
        result = fetcher.fetch(cursor=None, batch_size=10)

        assert result.error is None
        assert result.is_bootstrap is True
        assert len(result.records) == 2
        assert result.records[0]["id"] == "GHSA-1111-2222-3333"
        assert result.metadata["ecosystem"] == "npm"
