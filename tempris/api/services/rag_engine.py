"""
Tempris RAG Engine — Retrieval-Augmented Generation via ChromaDB
Provides semantic search over policies, KEV data, compliance frameworks,
and audit logs to ground AI responses in precise, relevant context.
"""
import os
import re
import hashlib
import logging
from typing import Optional

logger = logging.getLogger("tempris.rag")

# ── ChromaDB Configuration ────────────────────────────────────────────────────

CHROMA_PERSIST_DIR = os.environ.get("CHROMA_PERSIST_DIR", "/app/data/chroma")

# Lazy-initialized singleton
_client = None
_collection = None


def _get_collection():
    """Lazy-init the ChromaDB client and return the main collection."""
    global _client, _collection
    if _collection is not None:
        return _collection

    try:
        import chromadb
        from chromadb.config import Settings

        os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)

        _client = chromadb.PersistentClient(
            path=CHROMA_PERSIST_DIR,
            settings=Settings(anonymized_telemetry=False),
        )

        # Use ChromaDB's built-in default embedding function (ONNX all-MiniLM-L6-v2)
        # This is lightweight (~80MB) compared to sentence-transformers + PyTorch (~2GB)
        _collection = _client.get_or_create_collection(
            name="tempris_knowledge",
            metadata={"hnsw:space": "cosine"},
        )

        logger.info(
            f"ChromaDB initialized. Collection 'tempris_knowledge' has {_collection.count()} documents."
        )
        return _collection
    except Exception as e:
        logger.error(f"ChromaDB initialization failed: {e}")
        return None


# ── Document Chunking ─────────────────────────────────────────────────────────


def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    """Split text into overlapping chunks for embedding.
    
    Uses paragraph-aware splitting: tries to split on double newlines first,
    then falls back to sentence boundaries, then hard character limits.
    """
    if not text or not text.strip():
        return []

    # Split by paragraphs first (double newlines)
    paragraphs = re.split(r"\n\n+", text.strip())
    chunks = []
    current_chunk = ""

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        # If adding this paragraph stays within limit, append
        if len(current_chunk) + len(para) + 2 <= chunk_size:
            current_chunk = f"{current_chunk}\n\n{para}" if current_chunk else para
        else:
            # Save current chunk if non-empty
            if current_chunk:
                chunks.append(current_chunk.strip())
            
            # If single paragraph exceeds chunk_size, split by sentences
            if len(para) > chunk_size:
                sentences = re.split(r"(?<=[.!?])\s+", para)
                sub_chunk = ""
                for sent in sentences:
                    if len(sub_chunk) + len(sent) + 1 <= chunk_size:
                        sub_chunk = f"{sub_chunk} {sent}" if sub_chunk else sent
                    else:
                        if sub_chunk:
                            chunks.append(sub_chunk.strip())
                        sub_chunk = sent
                current_chunk = sub_chunk
            else:
                current_chunk = para

    if current_chunk:
        chunks.append(current_chunk.strip())

    return [c for c in chunks if len(c) > 20]  # Filter out tiny fragments


def _doc_hash(text: str) -> str:
    """Generate a deterministic hash for content deduplication."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ── Embedding Functions ──────────────────────────────────────────────────────


def embed_document(doc_id: str, text: str, metadata: dict | None = None):
    """Embed a single document into the vector store.
    
    Chunks the text, deduplicates by content hash, and upserts into ChromaDB.
    """
    collection = _get_collection()
    if collection is None:
        logger.warning("ChromaDB unavailable — skipping embed")
        return 0

    chunks = _chunk_text(text)
    if not chunks:
        return 0

    ids = []
    documents = []
    metadatas = []

    for i, chunk in enumerate(chunks):
        chunk_id = f"{doc_id}__chunk_{i}__{_doc_hash(chunk)}"
        meta = {"source": doc_id, "chunk_index": i, "total_chunks": len(chunks)}
        if metadata:
            meta.update(metadata)
        ids.append(chunk_id)
        documents.append(chunk)
        metadatas.append(meta)

    # Upsert to handle re-indexing gracefully
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    logger.info(f"Embedded {len(chunks)} chunks for document '{doc_id}'")
    return len(chunks)


def embed_documents_batch(docs: list[dict]):
    """Embed multiple documents in batch.
    
    Each doc should have: {"id": str, "text": str, "metadata": dict}
    """
    total = 0
    for doc in docs:
        total += embed_document(doc["id"], doc["text"], doc.get("metadata"))
    return total


# ── Semantic Search ───────────────────────────────────────────────────────────


def semantic_search(query: str, n_results: int = 5, source_filter: str | None = None) -> list[dict]:
    """Search the vector store for chunks most relevant to the query.
    
    Returns a list of dicts: [{"text": str, "source": str, "score": float}]
    """
    collection = _get_collection()
    if collection is None:
        return []

    if collection.count() == 0:
        return []

    where_filter = {"source": source_filter} if source_filter else None

    try:
        results = collection.query(
            query_texts=[query],
            n_results=min(n_results, collection.count()),
            where=where_filter,
        )
    except Exception as e:
        logger.warning(f"Semantic search failed: {e}")
        return []

    output = []
    if results and results.get("documents"):
        docs = results["documents"][0]
        metas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(docs)
        dists = results["distances"][0] if results.get("distances") else [0.0] * len(docs)

        for doc, meta, dist in zip(docs, metas, dists):
            output.append({
                "text": doc,
                "source": meta.get("source", "unknown"),
                "score": round(1.0 - dist, 4),  # cosine: distance → similarity
                "metadata": meta,
            })

    return output


# ── Knowledge Sync (called on startup) ────────────────────────────────────────


def sync_knowledge_base(db=None):
    """Sync all knowledge sources into the vector store.
    
    Called on application startup to ensure the vector DB is populated with:
    1. Policy documents (ISO 42001, Bug Bounty, Air-Gapped Readiness)
    2. CISA KEV vulnerability summaries (top critical CVEs)
    3. GRC control descriptions
    4. Compliance framework definitions
    5. Recent audit log context
    """
    collection = _get_collection()
    if collection is None:
        logger.warning("ChromaDB unavailable — skipping knowledge sync")
        return

    total_embedded = 0

    # ── 1. Policy Documents ───────────────────────────────────────────────
    docs_dir = os.path.join(os.path.dirname(__file__), "..", "docs")
    if os.path.isdir(docs_dir):
        for filename in os.listdir(docs_dir):
            if filename.endswith(".md"):
                filepath = os.path.join(docs_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                    doc_id = f"policy__{filename.replace('.md', '')}"
                    
                    # Check if already embedded with same content
                    content_hash = _doc_hash(content)
                    existing = collection.get(ids=[f"{doc_id}__chunk_0__{content_hash}"])
                    if existing and existing["ids"]:
                        logger.info(f"Policy '{filename}' unchanged — skipping re-embed")
                        continue
                    
                    # Delete old chunks for this document before re-embedding
                    _delete_by_source(doc_id)
                    
                    total_embedded += embed_document(doc_id, content, {
                        "type": "policy",
                        "filename": filename,
                    })
                except Exception as e:
                    logger.warning(f"Failed to embed policy {filename}: {e}")

    # ── 2. CISA KEV Critical CVE Summaries ────────────────────────────────
    try:
        from services.kev_loader import get_all_findings
        findings = get_all_findings()
        critical = [f for f in findings if f.get("priority") == "P0"]

        # Embed top 50 critical CVEs as individual documents
        cve_texts = []
        for f in critical[:50]:
            cve_text = (
                f"CVE: {f.get('cve', 'N/A')}\n"
                f"Title: {f.get('title', 'N/A')}\n"
                f"Vendor: {f.get('vendor', 'N/A')}\n"
                f"Product: {f.get('product', 'N/A')}\n"
                f"CVSS: {f.get('cvss', 0)}\n"
                f"Priority: {f.get('priority', 'N/A')}\n"
                f"Ransomware: {f.get('ransomware', False)}\n"
                f"Date Added: {f.get('date_added', 'N/A')}\n"
                f"Due Date: {f.get('due_date', 'N/A')}\n"
                f"Action: {f.get('action', 'N/A')}"
            )
            cve_texts.append(cve_text)

        if cve_texts:
            combined_cve = "\n\n---\n\n".join(cve_texts)
            _delete_by_source("kev__critical_cves")
            total_embedded += embed_document("kev__critical_cves", combined_cve, {
                "type": "vulnerability",
                "source_catalog": "CISA KEV",
            })

        # Also embed a KEV summary
        ransomware_count = len([f for f in findings if f.get("ransomware")])
        kev_summary = (
            f"CISA Known Exploited Vulnerabilities (KEV) Catalog Summary\n\n"
            f"Total vulnerabilities tracked: {len(findings)}\n"
            f"Critical (P0): {len(critical)}\n"
            f"Ransomware-linked: {ransomware_count}\n"
            f"This catalog is maintained by the Cybersecurity and Infrastructure Security Agency (CISA) "
            f"and contains vulnerabilities with confirmed active exploitation in the wild."
        )
        _delete_by_source("kev__summary")
        total_embedded += embed_document("kev__summary", kev_summary, {"type": "reference"})

    except Exception as e:
        logger.warning(f"Failed to embed KEV data: {e}")

    # ── 3. GRC Control Descriptions ───────────────────────────────────────
    try:
        from routers.grc import GRC_CONTROLS
        grc_text = "ISO/IEC 42001:2023 AI Governance Controls\n\n"
        for c in GRC_CONTROLS:
            grc_text += (
                f"Control {c['id']} — {c['domain']}: {c['title']}\n"
                f"  Singapore Reference: {c.get('sg_ref', 'N/A')}\n"
                f"  TES Modifier: {c.get('tes_modifier', 'N/A')} ({c.get('tes_impact', 'N/A')})\n"
                f"  Description: {c.get('description', 'N/A')}\n\n"
            )
        _delete_by_source("grc__controls")
        total_embedded += embed_document("grc__controls", grc_text, {"type": "compliance"})
    except Exception as e:
        logger.warning(f"Failed to embed GRC controls: {e}")

    # ── 4. Compliance Framework Definitions ───────────────────────────────
    try:
        from routers.standard import FRAMEWORKS
        for fw_id, fw in FRAMEWORKS.items():
            fw_text = f"Framework: {fw['name']}\n\n"
            for c in fw.get("controls", []):
                fw_text += f"  Control {c['id']}: {c['title']}\n    Default Status: {c.get('default_status', 'not_assessed')}\n"
            _delete_by_source(f"framework__{fw_id}")
            total_embedded += embed_document(f"framework__{fw_id}", fw_text, {
                "type": "compliance",
                "framework": fw_id,
            })
    except Exception as e:
        logger.warning(f"Failed to embed compliance frameworks: {e}")

    # ── 5. Recent Audit Logs ──────────────────────────────────────────────
    if db:
        try:
            from models import AuditLog
            recent_logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()
            if recent_logs:
                audit_text = "Recent TACF Audit Trail Entries\n\n"
                for log in recent_logs:
                    ts = log.timestamp.strftime("%Y-%m-%d %H:%M") if log.timestamp else "?"
                    audit_text += f"[{ts}] {log.module} — {log.action}: {(log.detail or '')[:120]}\n"
                _delete_by_source("tacf__recent_logs")
                total_embedded += embed_document("tacf__recent_logs", audit_text, {"type": "audit"})
        except Exception as e:
            logger.warning(f"Failed to embed audit logs: {e}")

    logger.info(f"Knowledge sync complete. Total chunks embedded: {total_embedded}. "
                f"Collection size: {collection.count()}")
    return total_embedded


def _delete_by_source(source_id: str):
    """Delete all chunks belonging to a specific source document."""
    collection = _get_collection()
    if collection is None or collection.count() == 0:
        return
    try:
        collection.delete(where={"source": source_id})
    except Exception:
        pass  # Ignore if nothing to delete


# ── Utility ───────────────────────────────────────────────────────────────────


def get_stats() -> dict:
    """Return vector store statistics."""
    collection = _get_collection()
    if collection is None:
        return {"status": "unavailable", "count": 0}
    return {
        "status": "active",
        "count": collection.count(),
        "persist_dir": CHROMA_PERSIST_DIR,
    }
