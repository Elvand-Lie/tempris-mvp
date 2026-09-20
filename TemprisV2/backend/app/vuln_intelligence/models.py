# backend/app/vuln_intelligence/models.py
"""
Pure-data domain objects for the vulnerability intelligence library.
No ORM — these are plain dataclasses used between the repository layer
and callers. JSON serialization stays in the caller or route layer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any, Optional

# CVE ID syntax: CVE-YYYY-NNNN+ (4-digit year, 4+ digit sequence)
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class AuthorityError(Exception):
    """Raised when a non-authoritative source attempts to write canonical data."""
    pass


class ArchiveError(Exception):
    """Base exception for archive processing failures."""
    pass


class PathTraversalError(ArchiveError):
    """Raised when an archive entry attempts path traversal / Zip Slip."""
    pass


class ArchiveBombError(ArchiveError):
    """Raised when an archive exceeds expansion limits or compression ratio (Zip Bomb)."""
    pass


class ArchiveFileCountExceededError(ArchiveError):
    """Raised when an archive contains more files than allowed."""
    pass


class ArchiveEntryTooLargeError(ArchiveError):
    """Raised when a single archive entry exceeds size limits."""
    pass


class ArchiveCorruptionError(ArchiveError):
    """Raised when an archive file is truncated, malformed, or corrupted."""
    pass


class MassWithdrawalExceededError(Exception):
    """Raised when a full snapshot drops more records than the safety threshold."""
    pass


@dataclass
class ArchiveLimits:
    """Resource and safety limits for archive decompression.

    Conservative shared defaults (P1-02 review): 500 MB compressed / 2 GB
    expanded / 500k files / 100:1 ratio / 300 s cumulative extraction —
    these are the bounds every consumer inherited before P1-02 and the
    correct bounds for the small, bounded in-memory artifacts (KEV catalog,
    daily EPSS CSV, OSV zips). The CVE/cvelistV5 staged bootstrap (the one
    ~300 MB compressed → ~3 GB expanded consumer) overrides via the
    CVE_ARCHIVE_LIMITS preset — the shared defaults are NOT resized around
    that single consumer (out-of-scope sources keep their behavior).
    """
    max_compressed_bytes: int = 500 * 1024 * 1024       # 500 MB max compressed archive
    max_expanded_bytes: int = 2 * 1024 * 1024 * 1024    # 2 GB max total uncompressed
    max_file_count: int = 500_000                       # 500k files max
    max_entry_bytes: int = 50 * 1024 * 1024             # 50 MB max per entry
    max_compression_ratio: float = 100.0                # 100:1 max ratio
    min_ratio_threshold_bytes: int = 1 * 1024 * 1024    # 1 MB min uncompressed to enforce ratio
    extraction_timeout_seconds: float = 300.0           # cumulative extraction budget


# CVE/cvelistV5-only preset (P1-02 review fix; compressed cap raised by the
# P1-03 hotfix): the live catalog measured 673,227,801 bytes compressed
# expanding to ~3.1 GB across ~396k files (ratio ~5.6:1) on 2026-09-20 — the
# previous 600 MB compressed cap failed closed against the real feed. Caps
# still carry margin over that reality; per-entry ratio/count/size guards are
# UNCHANGED so genuinely hostile archives still fail closed; the cumulative
# extraction timeout covers a one-time ~3 GB staged extraction at a
# conservative >= 2 MB/s sustained rate. Only CveFetchClient uses this.
CVE_ARCHIVE_LIMITS = ArchiveLimits(
    max_compressed_bytes=1024 * 1024 * 1024,      # 1 GiB compressed (live feed ~673 MB, 2026-09-20)
    max_expanded_bytes=6 * 1024 * 1024 * 1024,    # 6 GB expanded (2x over measured ~3.1 GB)
    max_file_count=500_000,                        # cvelistV5 ~396k files (2026-09-20)
    max_entry_bytes=50 * 1024 * 1024,
    max_compression_ratio=100.0,
    min_ratio_threshold_bytes=1 * 1024 * 1024,
    extraction_timeout_seconds=1800.0,             # one-time ~3 GB stage
)



def validate_cve_id(cve_id: str) -> bool:
    """Return True if cve_id matches the canonical CVE syntax."""
    return bool(CVE_ID_RE.match(cve_id))


@dataclass
class CanonicalVulnerability:
    cve_id: str
    state: str  # PUBLISHED | RESERVED | REJECTED
    date_published: Optional[datetime] = None
    date_updated: Optional[datetime] = None
    date_reserved: Optional[datetime] = None
    date_rejected: Optional[datetime] = None
    assigner_org_id: Optional[str] = None
    assigner_short_name: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class SourceRecord:
    id: Optional[str] = None
    source: str = ""           # cve | nvd | kev | epss | osv
    source_id: str = ""        # e.g. CVE-2024-1234 or GHSA-xxxx
    cve_id: Optional[str] = None
    declared_cve_id: Optional[str] = None  # Sprint 01: always-set CVE string, no FK
    content_hash: str = ""     # SHA-256 of canonical payload
    raw_payload: Any = None    # full source-native record (dict)
    source_updated_at: Optional[datetime] = None
    is_current: bool = True
    snapshot_id: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass
class CvssAssessment:
    id: Optional[str] = None
    cve_id: str = ""
    source: str = ""           # cve | nvd
    assessor: str = ""         # CNA org, nvd@nist.gov, etc.
    assessment_type: Optional[str] = None  # Primary/Secondary or cna/adp
    container_role: Optional[str] = None   # cna | adp | nvd (Sprint 03)
    provider_org_id: Optional[str] = None  # Org ID of assessor (Sprint 03)
    cvss_version: str = ""     # 2.0 | 3.0 | 3.1 | 4.0
    vector_string: str = ""
    base_score: Decimal = Decimal("0")
    base_severity: Optional[str] = None
    exploitability_score: Optional[Decimal] = None
    impact_score: Optional[Decimal] = None
    scenario: str = "GENERAL"
    raw_data: Any = None
    source_record_id: Optional[str] = None
    is_current: bool = True
    created_at: Optional[datetime] = None


@dataclass
class CveRelationship:
    id: Optional[str] = None
    cve_id: str = ""
    related_cve_id: str = ""
    relationship_type: str = ""  # replaced_by | replaces | related | ...
    source: str = ""
    source_record_id: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass
class CveAffected:
    id: Optional[str] = None
    cve_id: str = ""
    source: str = ""
    vendor: Optional[str] = None
    product: Optional[str] = None
    versions: Any = None       # JSONB
    cpes: Optional[list] = None
    default_status: Optional[str] = None
    raw_data: Any = None
    source_record_id: Optional[str] = None
    is_current: bool = True
    created_at: Optional[datetime] = None


@dataclass
class KevEntry:
    id: Optional[str] = None
    cve_id: Optional[str] = None  # Sprint 01: nullable FK, NULL until canonical exists
    declared_cve_id: str = ""     # Sprint 01: always-set CVE string, no FK
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: Optional[date] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[date] = None
    known_ransomware: Optional[str] = None
    notes: Optional[str] = None
    source_record_id: Optional[str] = None
    is_active: bool = True
    withdrawn_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class EpssScore:
    id: Optional[str] = None
    cve_id: str = ""
    score: Decimal = Decimal("0")
    percentile: Decimal = Decimal("0")
    model_version: Optional[str] = None
    score_date: Optional[date] = None
    source_record_id: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass
class OsvRecord:
    osv_id: str = ""
    summary: Optional[str] = None
    details: Optional[str] = None
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    withdrawn: Optional[datetime] = None
    ecosystem: Optional[str] = None
    package_name: Optional[str] = None
    package_purl: Optional[str] = None
    affected_ranges: Any = None
    severity: Any = None
    database_specific: Any = None
    references: Any = None
    raw_payload: Any = None
    source_record_id: Optional[str] = None
    schema_version: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class OsvAlias:
    id: Optional[str] = None
    osv_id: str = ""
    alias: str = ""
    alias_type: str = "alias"  # alias | related
    linked_cve_id: Optional[str] = None
    declared_linked_cve_id: Optional[str] = None  # Sprint 01: always-set CVE string, no FK
    created_at: Optional[datetime] = None


@dataclass
class CveAdpEntry:
    id: Optional[str] = None
    cve_id: str = ""
    provider_org_id: str = ""
    provider_short_name: Optional[str] = None
    date_updated: Optional[datetime] = None
    title: Optional[str] = None
    ssvc_data: Any = None
    raw_data: Any = None
    source_record_id: Optional[str] = None
    is_current: bool = True
    created_at: Optional[datetime] = None


@dataclass
class SyncSnapshot:
    id: Optional[str] = None
    source: str = ""
    sync_mode: str = ""        # bootstrap | incremental
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "running"    # running | completed | failed | partial
    records_processed: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_unchanged: int = 0
    records_failed: int = 0
    error_message: Optional[str] = None
    cursor_before: Optional[str] = None
    cursor_after: Optional[str] = None
    metadata: Any = None
    created_at: Optional[datetime] = None


@dataclass
class SyncState:
    source: str = ""
    cursor_value: Optional[str] = None
    last_successful_at: Optional[datetime] = None
    last_attempted_at: Optional[datetime] = None
    last_error: Optional[str] = None
    # Operational last-attempt pointer: advances on success AND on failure
    # (the failed attempt's snapshot). Never authoritative for resolvers.
    last_snapshot_id: Optional[str] = None
    # Authoritative last-good generation pointer (migration 009): advances
    # only on successful import. EPSS/KEV resolvers bind to THIS.
    last_good_snapshot_id: Optional[str] = None
    consecutive_failures: int = 0
    is_healthy: bool = True
    config: Any = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# P0-03 resolver result types (PRD-000 v1.8 §3.5 #2, §3.3.3)
# ---------------------------------------------------------------------------

# Stable, distinct reason codes for the CVE intelligence resolvers (P0-03).
# These are contract values: consumers (including the future P0-04 TES engine)
# may match on them, so they must never be renamed casually.
CVSS_MISSING_CVE = "cvss_missing_cve"
CVSS_NO_AUTHORITATIVE_ASSESSMENT = "cvss_no_authoritative_assessment"
CVSS_AUTHORITY_AMBIGUOUS = "cvss_authority_ambiguous"
EPSS_MISSING_SYNC_STATE = "epss_missing_sync_state"
EPSS_UNHEALTHY = "epss_unhealthy"
EPSS_NEVER_IMPORTED = "epss_never_imported"
EPSS_STALE = "epss_stale"
EPSS_MISSING_SNAPSHOT = "epss_missing_snapshot"
EPSS_NO_OBSERVATION = "epss_no_observation"
KEV_MISSING_SYNC_STATE = "kev_missing_sync_state"
KEV_UNHEALTHY = "kev_unhealthy"
KEV_NEVER_IMPORTED = "kev_never_imported"
KEV_STALE = "kev_stale"
KEV_MISSING_SNAPSHOT = "kev_missing_snapshot"

# Freshness window (PRD §3.3.3, locked v1.8): a feed observation is fresh only
# when the last successful import is no more than 48 hours old. Exactly 48
# hours is fresh; beyond is stale. This is a policy constant, deliberately
# decoupled from the mutable sync_interval_seconds scheduling value.
FEED_FRESHNESS_WINDOW = timedelta(hours=48)


@dataclass(frozen=True)
class ResolverProvenance:
    """Feed-health provenance shared by the EPSS and KEV resolvers.

    ``freshness_age_seconds`` is the age of the last successful import at the
    evaluation instant (as_of), and is None only when the import never ran.

    The two snapshot pointers are deliberately distinct:
      * ``last_snapshot_id`` — operational last-ATTEMPT metadata (a failed
        import advances it); never authoritative.
      * ``last_good_snapshot_id`` — the authoritative last-good generation
        the resolver actually bound to.
    """
    source: str
    is_healthy: Optional[bool] = None
    last_successful_at: Optional[datetime] = None
    last_snapshot_id: Optional[str] = None
    last_good_snapshot_id: Optional[str] = None
    freshness_age_seconds: Optional[float] = None


@dataclass
class CvssAuthorityResolution:
    """Result of the deterministic CVSS authority resolver (PRD §3.5 #2).

    Selection: is_current rows only -> newest supported version
    (4.0 > 3.1 > 3.0 > 2.0) -> within version CNA > NVD > ADP
    (structural container_role) -> more than one surviving row is a
    fail-closed ambiguity, never tie-broken.

    Unscoreable results carry ``reason_code`` (one of the CVSS_* constants)
    and a human-readable ``reason``. When ambiguous, ``ambiguous_rows``
    carries the full provenance of every surviving winning row so the data
    defect is inspectable.
    """
    cve_id: str
    assessment_id: Optional[str] = None
    version: Optional[str] = None
    role: Optional[str] = None              # 'cna' | 'nvd' | 'adp'
    assessor: Optional[str] = None
    provider_org_id: Optional[str] = None
    scenario: Optional[str] = None
    score: Optional[Decimal] = None
    severity: Optional[str] = None
    vector: Optional[str] = None
    source: Optional[str] = None            # 'cve' | 'nvd'
    source_record_id: Optional[str] = None
    created_at: Optional[datetime] = None
    is_current: Optional[bool] = None
    ambiguous_rows: Optional[list[dict]] = None
    reason_code: Optional[str] = None
    reason: Optional[str] = None

    @property
    def is_scoreable(self) -> bool:
        return self.score is not None


@dataclass(frozen=True)
class EpssFreshnessResolution:
    """Structured EPSS freshness resolver result (P0-03).

    ``state`` is 'fresh' | 'unknown'; ``reason_code`` is None for fresh and a
    stable EPSS_* constant otherwise. The TES EPSS ladder is P0-04's — this
    resolver returns the observation and its provenance only.

    ``snapshot_id`` is the authoritative last-good generation the observation
    is bound to (never the operational last-attempt pointer).
    """
    cve_id: str
    state: str                                   # 'fresh' | 'unknown'
    reason_code: Optional[str] = None
    reason: Optional[str] = None
    score: Optional[Decimal] = None
    percentile: Optional[Decimal] = None
    model_version: Optional[str] = None
    score_date: Optional[date] = None
    source_record_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    provenance: Optional[ResolverProvenance] = None

    @property
    def is_fresh(self) -> bool:
        return self.state == "fresh"


@dataclass(frozen=True)
class KevTernaryResolution:
    """Ternary KEV resolver result (P0-03): listed / not_listed / unknown.

    ``listed``/``not_listed`` require a fresh, healthy feed whose consulted
    membership is bound to the exact authoritative last-good snapshot
    (``last_good_snapshot_id``). Absence on a stale/unhealthy feed or one
    without a last-good generation is ``unknown`` — never silently
    "not listed".

    ``snapshot_id`` is the authoritative last-good generation consulted (also
    set on fresh ``not_listed`` results), never the operational last-attempt
    pointer.
    """
    cve_id: str
    state: str                                   # 'listed' | 'not_listed' | 'unknown'
    reason_code: Optional[str] = None
    reason: Optional[str] = None
    entry_id: Optional[str] = None
    declared_cve_id: Optional[str] = None
    resolved_cve_id: Optional[str] = None
    known_ransomware: Optional[str] = None
    date_added: Optional[date] = None
    source_record_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    provenance: Optional[ResolverProvenance] = None

    @property
    def is_unknown(self) -> bool:
        return self.state == "unknown"


@dataclass
class SourceArtifact:
    """Exact downloaded artifact bytes with provenance metadata."""
    id: Optional[str] = None
    source_record_id: str = ""
    sha256_hash: str = ""
    artifact_url: Optional[str] = None
    media_type: Optional[str] = None
    byte_size: int = 0
    artifact_bytes: Optional[bytes] = None
    retrieval_time: Optional[datetime] = None
    importer_version: Optional[str] = None
    created_at: Optional[datetime] = None
