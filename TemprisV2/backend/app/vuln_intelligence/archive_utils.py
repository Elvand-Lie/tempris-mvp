# backend/app/vuln_intelligence/archive_utils.py
"""
Bounded archive processing utilities with strict resource and hostile archive guards.
Governing Contract 8 / VI-QA-07:
  - Bounded size, expansion, file count, and per-entry byte limits
  - Zip Slip / path traversal protection (.., leading /, drive letters, null bytes, escaping symlinks)
  - Zip Bomb protection with minimum size threshold (1 MB) to avoid false positives on small files
  - Safe streaming and chunked decompression (gzip & zip)
  - Temporary file cleanup guarantee via context managers / try-finally
  - Explicit error hierarchy (ArchiveError, PathTraversalError, ArchiveBombError,
    ArchiveFileCountExceededError, ArchiveEntryTooLargeError, ArchiveCorruptionError)
"""
from __future__ import annotations

import gzip
import io
import logging
import os
import pathlib
import re
import shutil
import struct
import tempfile
import time
import zipfile
import zlib
from contextlib import contextmanager
from typing import Generator, Iterator, Optional, Union

from app.vuln_intelligence.models import (
    ArchiveLimits,
    ArchiveError,
    PathTraversalError,
    ArchiveBombError,
    ArchiveFileCountExceededError,
    ArchiveEntryTooLargeError,
    ArchiveCorruptionError,
)

logger = logging.getLogger(__name__)

# Patterns for hostile archive entry paths
_DRIVE_LETTER_RE = re.compile(r"^[a-zA-Z]:")


def validate_archive_path(filename: str) -> str:
    """
    Validate that an archive member path does not attempt path traversal (Zip Slip).
    Rejects:
      - Null bytes (\0)
      - Leading slashes (/ or \\)
      - Drive letters (e.g. C:, D:)
      - Directory traversal segments (..)
      - Paths that resolve outside the relative root
    Raises PathTraversalError if invalid. Returns normalized relative path on success.
    """
    if "\0" in filename:
        raise PathTraversalError(f"Null byte in archive member path: {filename!r}")

    # Check for drive letters (e.g. C:\boot.ini or C:foo)
    if _DRIVE_LETTER_RE.match(filename):
        raise PathTraversalError(f"Drive letter in archive member path: {filename!r}")

    # Check for leading slashes
    if filename.startswith("/") or filename.startswith("\\"):
        raise PathTraversalError(f"Leading slash in archive member path: {filename!r}")

    # Check components for .. segments
    normalized = os.path.normpath(filename).replace("\\", "/")
    if normalized == ".." or normalized.startswith("../") or "/../" in normalized or normalized.endswith("/.."):
        raise PathTraversalError(f"Directory traversal segment in archive member path: {filename!r}")

    # Explicit check on parts
    p = pathlib.PurePosixPath(filename.replace("\\", "/"))
    if ".." in p.parts:
        raise PathTraversalError(f"Directory traversal segment in archive member path: {filename!r}")
    if p.is_absolute():
        raise PathTraversalError(f"Absolute path in archive member path: {filename!r}")

    return normalized


def safe_extract_zip(
    archive_input: Union[bytes, io.BytesIO, str, pathlib.Path],
    limits: Optional[ArchiveLimits] = None,
) -> Generator[tuple[str, bytes], None, None]:
    """
    Safely extract entries from a zip archive in memory / streaming fashion.
    Yields (normalized_filename, content_bytes) for each file entry.

    Guards:
      - Compressed size <= limits.max_compressed_bytes
      - File count <= limits.max_file_count
      - Path traversal / Zip Slip validation on every entry
      - Per-entry uncompressed size <= limits.max_entry_bytes
      - Total uncompressed size <= limits.max_expanded_bytes
      - Compression ratio <= limits.max_compression_ratio (enforced when uncompressed >= min_ratio_threshold_bytes)
      - Corruption / malformed zip raises ArchiveCorruptionError
    """
    lim = limits or ArchiveLimits()
    start_time = time.time()

    # Determine compressed size if available
    compressed_bytes_len = 0
    if isinstance(archive_input, bytes):
        compressed_bytes_len = len(archive_input)
        if compressed_bytes_len > lim.max_compressed_bytes:
            raise ArchiveBombError(
                f"Compressed archive size ({compressed_bytes_len} bytes) exceeds limit ({lim.max_compressed_bytes} bytes)"
            )
        file_obj: Union[io.BytesIO, str, pathlib.Path] = io.BytesIO(archive_input)
    elif isinstance(archive_input, io.BytesIO):
        pos = archive_input.tell()
        archive_input.seek(0, io.SEEK_END)
        compressed_bytes_len = archive_input.tell()
        archive_input.seek(pos)
        if compressed_bytes_len > lim.max_compressed_bytes:
            raise ArchiveBombError(
                f"Compressed archive size ({compressed_bytes_len} bytes) exceeds limit ({lim.max_compressed_bytes} bytes)"
            )
        file_obj = archive_input
    elif isinstance(archive_input, (str, pathlib.Path)):
        p = pathlib.Path(archive_input)
        if not p.exists():
            raise ArchiveCorruptionError(f"Archive file does not exist: {archive_input}")
        compressed_bytes_len = p.stat().st_size
        if compressed_bytes_len > lim.max_compressed_bytes:
            raise ArchiveBombError(
                f"Compressed archive size ({compressed_bytes_len} bytes) exceeds limit ({lim.max_compressed_bytes} bytes)"
            )
        file_obj = str(p)
    else:
        file_obj = archive_input

    try:
        zf = zipfile.ZipFile(file_obj, "r")
    except (zipfile.BadZipFile, EOFError, struct.error, zlib.error, Exception) as e:
        if isinstance(e, ArchiveError):
            raise
        raise ArchiveCorruptionError(f"Malformed or corrupted zip archive: {e}") from e

    total_expanded_bytes = 0

    with zf:
        infolist = zf.infolist()
        if len(infolist) > lim.max_file_count:
            raise ArchiveFileCountExceededError(
                f"Archive contains {len(infolist)} files, exceeding limit ({lim.max_file_count})"
            )

        for info in infolist:
            # Check timeout
            if time.time() - start_time > lim.extraction_timeout_seconds:
                raise ArchiveError(f"Archive extraction timed out after {lim.extraction_timeout_seconds}s")

            # Validate path traversal / zip slip
            norm_name = validate_archive_path(info.filename)

            # Skip directory entries
            if info.is_dir() or norm_name.endswith("/"):
                continue

            # Check uncompressed header size
            if info.file_size > lim.max_entry_bytes:
                raise ArchiveEntryTooLargeError(
                    f"Entry {norm_name!r} size ({info.file_size} bytes) exceeds limit ({lim.max_entry_bytes} bytes)"
                )

            # Check entry-level ratio guard if uncompressed >= 1MB
            if info.file_size >= lim.min_ratio_threshold_bytes and info.compress_size > 0:
                entry_ratio = info.file_size / info.compress_size
                if entry_ratio > lim.max_compression_ratio:
                    raise ArchiveBombError(
                        f"Entry {norm_name!r} compression ratio ({entry_ratio:.1f}:1) exceeds limit ({lim.max_compression_ratio}:1)"
                    )

            # Streaming read of entry data in chunks to prevent unbounded memory allocation
            try:
                with zf.open(info, "r") as entry_file:
                    chunks = []
                    entry_bytes_read = 0
                    while True:
                        chunk = entry_file.read(64 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        entry_bytes_read += len(chunk)
                        total_expanded_bytes += len(chunk)

                        # Enforce total expanded bytes guard
                        if total_expanded_bytes > lim.max_expanded_bytes:
                            raise ArchiveBombError(
                                f"Total expanded archive size ({total_expanded_bytes} bytes) exceeds limit ({lim.max_expanded_bytes} bytes)"
                            )

                        # Enforce per-entry bytes guard mid-stream
                        if entry_bytes_read > lim.max_entry_bytes:
                            raise ArchiveEntryTooLargeError(
                                f"Entry {norm_name!r} read size ({entry_bytes_read} bytes) exceeds limit ({lim.max_entry_bytes} bytes)"
                            )

                        # Enforce cumulative ratio guard if uncompressed >= min threshold
                        if total_expanded_bytes >= lim.min_ratio_threshold_bytes and compressed_bytes_len > 0:
                            cum_ratio = total_expanded_bytes / compressed_bytes_len
                            if cum_ratio > lim.max_compression_ratio:
                                raise ArchiveBombError(
                                    f"Cumulative compression ratio ({cum_ratio:.1f}:1) exceeds limit ({lim.max_compression_ratio}:1)"
                                )

                    content_bytes = b"".join(chunks)
            except (zipfile.BadZipFile, zlib.error, EOFError) as e:
                raise ArchiveCorruptionError(f"Corrupted entry {norm_name!r}: {e}") from e

            yield (norm_name, content_bytes)


def safe_extract_gzip_chunks(
    gz_data: Union[bytes, io.BytesIO],
    limits: Optional[ArchiveLimits] = None,
    chunk_size: int = 64 * 1024,
) -> Generator[bytes, None, None]:
    """
    Safely stream decompressed chunks from a gzip payload.
    Aborts mid-stream immediately if expansion or ratio limits are exceeded.
    """
    lim = limits or ArchiveLimits()
    start_time = time.time()

    if isinstance(gz_data, bytes):
        compressed_len = len(gz_data)
        if compressed_len > lim.max_compressed_bytes:
            raise ArchiveBombError(
                f"Compressed gzip size ({compressed_len} bytes) exceeds limit ({lim.max_compressed_bytes} bytes)"
            )
        bio = io.BytesIO(gz_data)
    else:
        pos = gz_data.tell()
        gz_data.seek(0, io.SEEK_END)
        compressed_len = gz_data.tell()
        gz_data.seek(pos)
        if compressed_len > lim.max_compressed_bytes:
            raise ArchiveBombError(
                f"Compressed gzip size ({compressed_len} bytes) exceeds limit ({lim.max_compressed_bytes} bytes)"
            )
        bio = gz_data

    total_expanded = 0
    try:
        with gzip.GzipFile(fileobj=bio, mode="rb") as gz:
            while True:
                if time.time() - start_time > lim.extraction_timeout_seconds:
                    raise ArchiveError(f"Gzip decompression timed out after {lim.extraction_timeout_seconds}s")

                chunk = gz.read(chunk_size)
                if not chunk:
                    break
                total_expanded += len(chunk)

                if total_expanded > lim.max_expanded_bytes:
                    raise ArchiveBombError(
                        f"Gzip expanded size ({total_expanded} bytes) exceeds limit ({lim.max_expanded_bytes} bytes)"
                    )

                if total_expanded >= lim.min_ratio_threshold_bytes and compressed_len > 0:
                    ratio = total_expanded / compressed_len
                    if ratio > lim.max_compression_ratio:
                        raise ArchiveBombError(
                            f"Gzip compression ratio ({ratio:.1f}:1) exceeds limit ({lim.max_compression_ratio}:1)"
                        )

                yield chunk
    except (gzip.BadGzipFile, zlib.error, EOFError, OSError) as e:
        if isinstance(e, ArchiveError):
            raise
        raise ArchiveCorruptionError(f"Corrupted or malformed gzip stream: {e}") from e


def safe_extract_gzip(
    gz_data: Union[bytes, io.BytesIO],
    limits: Optional[ArchiveLimits] = None,
) -> bytes:
    """
    Safely decompress a gzip archive into memory bytes.
    Aborts immediately if bounds are exceeded without buffering excess data.
    """
    chunks = list(safe_extract_gzip_chunks(gz_data, limits=limits))
    return b"".join(chunks)


@contextmanager
def safe_extract_to_temp_dir(
    archive_input: Union[bytes, io.BytesIO, str, pathlib.Path],
    limits: Optional[ArchiveLimits] = None,
) -> Iterator[pathlib.Path]:
    """
    Extract zip archive to a temporary directory with guaranteed cleanup.
    Guarantees zero orphaned temporary files on disk even if an exception is raised.
    """
    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="tempris_extract_"))
    try:
        for filename, content in safe_extract_zip(archive_input, limits=limits):
            target_path = temp_dir / filename
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(content)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
