# backend/app/vuln_intelligence/cve_staging.py
"""
Persistent disk staging for the cve (cvelistV5) bootstrap (P1-02 Defect 1).

The full cvelistV5 catalog (~300 MB zip → ~3 GB extracted, ~280k JSON files)
cannot be re-downloaded and re-parsed into RAM on every 1000-record
continuation round. This module stages the extraction ONCE per bootstrap in a
persistent directory whose lifetime spans CLI invocations, and lets each
continuation round slice its batch straight from disk, parsing entries on
demand. The full parsed catalog is never resident in RAM.

Identity / resume invariant (the anti-stale-label rule):

    An offset-based continuation cursor may ONLY resume against the identical
    extraction it was created from.

Enforcement: every download gets a fresh random `stage_nonce`; the stage
identity is a digest over the walk of the extracted tree (relative path +
size per entry) salted with that nonce. A continuation cursor carries the
identity; every resume recomputes it from disk. A missing stage, a different
download (different nonce), an altered tree (added/removed/resized files) or
a corrupt manifest all fail validation and the bootstrap RESTARTS from batch
0. Reprocessing batches is harmless: every adapter write is a content-hash
upsert, so a restarted bootstrap converges to the same state.

Residual, documented limit: content-identical byte edits that preserve file
size are not detected by the walk digest. Machine-local staging tampering is
outside the threat model; the defect class being prevented is identity
confusion between two different downloads (the EPSS stale-label class), which
the per-download nonce defeats completely.

Staging lifecycle:
  - `stage_archive()` wipes and replaces the stage (one identity at a time).
  - A crashed chain's stage is resumable: the cursor still carries the
    identity and `load_staged_catalog()` restores the handle.
  - On chain exhaustion the engine calls `clear_staging()` (and a fresh
    bootstrap implicitly replaces any stale stage).
  - Disk requirement for the ops stage: ~3 GB free in the staging volume.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import pathlib
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.vuln_intelligence.archive_utils import safe_extract_zip
from app.vuln_intelligence.models import ArchiveLimits

logger = logging.getLogger(__name__)

STAGING_BASE_ENV = "TEMPRIS_VULN_STAGING_DIR"
_MANIFEST_NAME = "manifest.json"
_ENTRIES_DIR_NAME = "entries"


def staging_root() -> pathlib.Path:
    """Root directory of the cve stage (env-overridable, deterministic)."""
    base = os.environ.get(STAGING_BASE_ENV)
    if base:
        return pathlib.Path(base) / "cve"
    return pathlib.Path(tempfile.gettempdir()) / "tempris-vuln-staging" / "cve"


def clear_staging() -> None:
    """Remove the cve stage entirely (chain-exhaustion cleanup / fresh stage)."""
    root = staging_root()
    shutil.rmtree(root, ignore_errors=True)


def _walk_entries(entries_dir: pathlib.Path) -> list[tuple[str, int]]:
    """Sorted (relative posix path, byte size) walk of the extracted tree."""
    walked: list[tuple[str, int]] = []
    for dirpath, _dirnames, filenames in os.walk(entries_dir):
        for name in filenames:
            p = pathlib.Path(dirpath) / name
            rel = p.relative_to(entries_dir).as_posix()
            walked.append((rel, p.stat().st_size))
    walked.sort()
    return walked


def _compute_identity(nonce: str, walked: list[tuple[str, int]]) -> str:
    """Identity of one specific extraction instance (nonce-salted walk digest)."""
    h = hashlib.sha256()
    h.update(nonce.encode("utf-8"))
    h.update(b"\n")
    for rel, size in walked:
        h.update(f"{rel}:{size}\n".encode("utf-8"))
    return h.hexdigest()


@dataclass
class StagedCveCatalog:
    """Handle onto a validated on-disk extraction of one cvelistV5 download."""
    identity: str
    nonce: str
    downloaded_at: str
    source_url: str
    download_bytes: int
    entries_dir: pathlib.Path
    _entries: Optional[list[tuple[str, int]]] = field(default=None, repr=False)

    @property
    def entry_count(self) -> int:
        self._ensure_entries()
        return len(self._entries)  # type: ignore[union-attr]

    def _ensure_entries(self) -> None:
        if self._entries is None:
            self._entries = _walk_entries(self.entries_dir)

    def entry_paths(self) -> list[pathlib.Path]:
        """All staged JSON entry files, sorted, newest walk only."""
        self._ensure_entries()
        return [self.entries_dir / rel for rel, _size in self._entries]  # type: ignore[union-attr]

    def entry_slice(self, offset: int, batch_size: int) -> list[pathlib.Path]:
        return self.entry_paths()[offset : offset + batch_size]

    def read_entries(self, paths: list[pathlib.Path]) -> list[dict]:
        """Parse staged entries on demand; unparseable files are skipped with a
        warning (mirrors the previous in-memory parse behavior)."""
        import json as _json

        records: list[dict] = []
        for p in paths:
            try:
                data = _json.loads(p.read_bytes().decode("utf-8"))
                if isinstance(data, dict) and data.get("dataType") == "CVE_RECORD":
                    records.append(data)
                else:
                    logger.warning("Staged CVE entry %s is not a CVE_RECORD; skipped", p.name)
            except Exception as parse_err:  # noqa: BLE001 - mirrors previous per-entry tolerance
                logger.warning("Failed parsing staged CVE entry %s: %s", p.name, parse_err)
        return records


def _write_manifest(root: pathlib.Path, manifest: dict) -> None:
    (root / _MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")


def stage_archive(
    archive_input,
    *,
    limits: Optional[ArchiveLimits] = None,
    source_url: str = "",
) -> StagedCveCatalog:
    """
    Validate + extract one cvelistV5 zip download into the persistent stage,
    replacing any previous stage. All archive-safety guards (bomb, traversal,
    count, size, timeout) run exactly as in the in-memory path.
    """
    limits = limits or ArchiveLimits()
    root = staging_root()
    # One identity at a time: replace any previous stage.
    shutil.rmtree(root, ignore_errors=True)
    entries_dir = root / _ENTRIES_DIR_NAME
    entries_dir.mkdir(parents=True, exist_ok=True)

    for filename, content in safe_extract_zip(archive_input, limits=limits):
        if not filename.endswith(".json") or filename.startswith("__MACOSX"):
            continue
        target = entries_dir / filename
        resolved_target = target.resolve()
        if not str(resolved_target).startswith(str(entries_dir.resolve())):
            # Defense in depth; safe_extract_zip already validates paths.
            raise ValueError(f"Staged path escapes entries dir: {filename}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    nonce = uuid.uuid4().hex
    walked = _walk_entries(entries_dir)
    identity = _compute_identity(nonce, walked)
    manifest = {
        "identity": identity,
        "nonce": nonce,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "source_url": source_url,
        "download_bytes": len(archive_input) if isinstance(archive_input, (bytes, bytearray)) else None,
        "entry_count": len(walked),
    }
    _write_manifest(root, manifest)
    logger.info(
        "CVE bootstrap staged: identity=%s entries=%d bytes=%s",
        identity[:16], len(walked), manifest["download_bytes"],
    )
    return StagedCveCatalog(
        identity=identity,
        nonce=nonce,
        downloaded_at=manifest["downloaded_at"],
        source_url=source_url,
        download_bytes=manifest["download_bytes"] or 0,
        entries_dir=entries_dir,
        _entries=walked,
    )


def load_staged_catalog() -> Optional[StagedCveCatalog]:
    """
    Load and VALIDATE the persistent stage for resume. Returns None when the
    stage is absent or fails validation (missing/corrupt manifest, entry-count
    drift, identity mismatch with the walk) — the caller must restart the
    bootstrap from batch 0 in that case.
    """
    root = staging_root()
    manifest_path = root / _MANIFEST_NAME
    entries_dir = root / _ENTRIES_DIR_NAME
    if not manifest_path.is_file() or not entries_dir.is_dir():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        identity = manifest["identity"]
        nonce = manifest["nonce"]
        expected_count = int(manifest["entry_count"])
    except Exception as exc:  # noqa: BLE001 - corrupt manifest => restart
        logger.warning("CVE staging manifest unreadable (%s); bootstrap will restart", exc)
        return None

    walked = _walk_entries(entries_dir)
    if len(walked) != expected_count:
        logger.warning(
            "CVE staging entry drift (%d on disk vs %d in manifest); bootstrap will restart",
            len(walked), expected_count,
        )
        return None
    if _compute_identity(nonce, walked) != identity:
        logger.warning("CVE staging identity mismatch; bootstrap will restart")
        return None

    return StagedCveCatalog(
        identity=identity,
        nonce=nonce,
        downloaded_at=manifest.get("downloaded_at", ""),
        source_url=manifest.get("source_url", ""),
        download_bytes=manifest.get("download_bytes") or 0,
        entries_dir=entries_dir,
        _entries=walked,
    )
