"""
SQLite WAL persistence for decision receipts, Gate A review dispositions,
and Gate B remediation proposals.

Writes are idempotent (INSERT OR IGNORE / INSERT OR REPLACE) and survive
process restarts. We use WAL journal mode so reads don't block writes.
"""
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# WAL-mode database path
_DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "audit_store.db"

_write_lock = threading.Lock()


# Schema DDL

_DDL_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS decision_receipts (
        receipt_id       TEXT PRIMARY KEY,
        tenant_id        TEXT NOT NULL,
        finding_id       TEXT NOT NULL,
        verdict          TEXT NOT NULL CHECK(verdict IN ('EXONERATED','DEGRADED','CULPABLE','INDETERMINATE')),
        world_time       TEXT NOT NULL,
        knowledge_time   TEXT NOT NULL,
        signals          TEXT NOT NULL,    -- JSON: {p1, p2, p3, p4}
        canonical_sha256 TEXT NOT NULL,    -- SHA-256 hex digest
        hmac_signature   TEXT NOT NULL,    -- HMAC-SHA256 hex
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_receipts_tenant_finding ON decision_receipts (tenant_id, finding_id)",
    "CREATE INDEX IF NOT EXISTS idx_receipts_digest ON decision_receipts (canonical_sha256)",
    """
    CREATE TABLE IF NOT EXISTS review_dispositions (
        disposition_id   TEXT PRIMARY KEY,
        receipt_id       TEXT NOT NULL REFERENCES decision_receipts(receipt_id),
        tenant_id        TEXT NOT NULL,
        reviewer_id      TEXT NOT NULL,    -- HMAC-pseudonymized identity
        disposition      TEXT NOT NULL CHECK(disposition IN ('APPROVED','REJECTED')),
        analyst_notes    TEXT,
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_dispositions_receipt ON review_dispositions (receipt_id)",
    """
    CREATE TABLE IF NOT EXISTS remediation_proposals (
        proposal_id      TEXT PRIMARY KEY,
        receipt_id       TEXT NOT NULL REFERENCES decision_receipts(receipt_id),
        tenant_id        TEXT NOT NULL,
        authorizer_id    TEXT NOT NULL,    -- HMAC-pseudonymized identity
        pr_url           TEXT,             -- External execution tracking URL / ref (optional)
        pr_status        TEXT NOT NULL CHECK(pr_status IN ('PENDING','DRAFT','OPEN','MERGED','CLOSED')),
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_proposals_receipt ON remediation_proposals (receipt_id)",
]


# Connection management

class DurableStore:
    """
    SQLite WAL-mode durable store for cross-restart audit persistence.

    Enforces:
    - WAL journal mode for concurrent read access
    - Foreign key constraints
    - All writes via parameterized statements only
    - Thread-safe single-writer lock
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = Path(db_path or _DEFAULT_DB_PATH)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def initialize(self) -> None:
        """Explicit initializer called by FastAPI lifespan."""
        self._initialize_schema()


    def _connect(self) -> sqlite3.Connection:
        """Open a connection with WAL mode and FK enforcement."""
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_schema(self) -> None:
        """Create all tables and indexes if they don't already exist."""
        with _write_lock:
            conn = self._connect()
            try:
                for ddl in _DDL_STATEMENTS:
                    conn.execute(ddl)
                conn.commit()
            finally:
                conn.close()

    @contextmanager
    def _writer(self):
        """Context manager for write operations with exclusive lock."""
        with _write_lock:
            conn = self._connect()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    @contextmanager
    def _reader(self):
        """Context manager for read operations (no lock needed in WAL mode)."""
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    # Receipt operations

    def write_receipt(
        self,
        receipt_id: str,
        tenant_id: str,
        finding_id: str,
        verdict: str,
        world_time: str,
        knowledge_time: str,
        signals: Dict[str, Any],
        canonical_sha256: str,
        hmac_signature: str,
    ) -> None:
        """Persist a decision receipt (idempotent: ignores duplicate receipt_id)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._writer() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO decision_receipts
                (receipt_id, tenant_id, finding_id, verdict, world_time, knowledge_time,
                 signals, canonical_sha256, hmac_signature, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id, tenant_id, finding_id, verdict,
                    world_time, knowledge_time,
                    json.dumps(signals, separators=(",", ":")),
                    canonical_sha256, hmac_signature, now,
                ),
            )

    def get_receipt(self, receipt_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a receipt by ID, scoped to tenant (IDOR-safe: returns None if wrong tenant)."""
        with self._reader() as conn:
            row = conn.execute(
                "SELECT * FROM decision_receipts WHERE receipt_id = ? AND tenant_id = ?",
                (receipt_id, tenant_id),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["signals"] = json.loads(result["signals"])
        return result

    def list_receipts_for_finding(
        self, finding_id: str, tenant_id: str
    ) -> List[Dict[str, Any]]:
        """Return all receipts for a finding, ordered by creation time."""
        with self._reader() as conn:
            rows = conn.execute(
                """
                SELECT * FROM decision_receipts
                WHERE finding_id = ? AND tenant_id = ?
                ORDER BY created_at ASC
                """,
                (finding_id, tenant_id),
            ).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["signals"] = json.loads(r["signals"])
            results.append(r)
        return results

    # Gate A disposition operations

    def write_review_disposition(
        self,
        disposition_id: str,
        receipt_id: str,
        tenant_id: str,
        reviewer_id: str,
        disposition: str,
        analyst_notes: Optional[str] = None,
    ) -> None:
        """Persist Gate A review disposition."""
        now = datetime.now(timezone.utc).isoformat()
        with self._writer() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO review_dispositions
                (disposition_id, receipt_id, tenant_id, reviewer_id, disposition, analyst_notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (disposition_id, receipt_id, tenant_id, reviewer_id, disposition, analyst_notes, now),
            )

    def get_review_disposition(self, receipt_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Fetch the Gate A disposition for a receipt (tenant-scoped)."""
        with self._reader() as conn:
            row = conn.execute(
                "SELECT * FROM review_dispositions WHERE receipt_id = ? AND tenant_id = ?",
                (receipt_id, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    # Gate B remediation proposal operations

    def write_remediation_proposal(
        self,
        proposal_id: str,
        receipt_id: str,
        tenant_id: str,
        authorizer_id: str,
        pr_status: str = "PENDING",
        pr_url: Optional[str] = None,
    ) -> None:
        """Persist a Gate B remediation proposal."""
        now = datetime.now(timezone.utc).isoformat()
        with self._writer() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO remediation_proposals
                (proposal_id, receipt_id, tenant_id, authorizer_id, pr_url, pr_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (proposal_id, receipt_id, tenant_id, authorizer_id, pr_url, pr_status, now),
            )

    def update_proposal_pr_url(
        self, proposal_id: str, tenant_id: str, pr_url: str, pr_status: str
    ) -> None:
        """Update a proposal's tracking reference and status."""
        with self._writer() as conn:
            conn.execute(
                "UPDATE remediation_proposals SET pr_url = ?, pr_status = ? WHERE proposal_id = ? AND tenant_id = ?",
                (pr_url, pr_status, proposal_id, tenant_id),
            )

    def get_remediation_proposal(self, receipt_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Fetch the Gate B proposal for a receipt (tenant-scoped)."""
        with self._reader() as conn:
            row = conn.execute(
                "SELECT * FROM remediation_proposals WHERE receipt_id = ? AND tenant_id = ?",
                (receipt_id, tenant_id),
            ).fetchone()
        return dict(row) if row else None


# Singleton

_store: Optional[DurableStore] = None


def get_durable_store(db_path: Optional[Path] = None) -> DurableStore:
    """Get or create the singleton DurableStore instance."""
    global _store
    if _store is None:
        _store = DurableStore(db_path=db_path)
    return _store
