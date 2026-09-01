# backend/app/vuln_intelligence/models.py
"""
Pure-data domain objects for the vulnerability intelligence library.
No ORM — these are plain dataclasses used between the repository layer
and callers. JSON serialization stays in the caller or route layer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
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
    """Resource and safety limits for archive decompression."""
    max_compressed_bytes: int = 500 * 1024 * 1024       # 500 MB max compressed archive
    max_expanded_bytes: int = 2 * 1024 * 1024 * 1024    # 2 GB max total uncompressed
    max_file_count: int = 500_000                       # 500k files max
    max_entry_bytes: int = 50 * 1024 * 1024             # 50 MB max per entry
    max_compression_ratio: float = 100.0                # 100:1 max ratio
    min_ratio_threshold_bytes: int = 1 * 1024 * 1024    # 1 MB min uncompressed to enforce ratio
    extraction_timeout_seconds: float = 300.0           # 300 seconds timeout



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
    last_snapshot_id: Optional[str] = None
    consecutive_failures: int = 0
    is_healthy: bool = True
    config: Any = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class TesResolution:
    """Result of the deterministic TES-input CVSS resolver."""
    cve_id: str
    resolved_score: Optional[Decimal] = None
    resolved_vector: Optional[str] = None
    resolved_severity: Optional[str] = None
    resolved_assessor: Optional[str] = None
    resolution_tier: Optional[str] = None  # 'cna' | 'nvd' | None
    unscoreable_reason: Optional[str] = None

    @property
    def is_scoreable(self) -> bool:
        return self.resolved_score is not None


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
