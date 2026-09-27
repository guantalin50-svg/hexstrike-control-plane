from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from .models import AuditRecord, Decision, JobRecord, JobRequest, JobStatus, PolicyEvaluation, utc_now


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    target TEXT NOT NULL,
                    arguments TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    requester TEXT NOT NULL,
                    dry_run INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    policy_reasons TEXT NOT NULL,
                    approved_by TEXT,
                    approval_reason TEXT,
                    result TEXT,
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    details TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )

    def create_job(
        self,
        request: JobRequest,
        evaluation: PolicyEvaluation,
        requester: str,
    ) -> JobRecord:
        job_id = str(uuid.uuid4())
        timestamp = utc_now()
        status = {
            Decision.ALLOW: JobStatus.READY,
            Decision.APPROVAL: JobStatus.PENDING_APPROVAL,
            Decision.DENY: JobStatus.DENIED,
        }[evaluation.decision]
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    id, created_at, updated_at, tool, target, arguments,
                    justification, requester, dry_run, status, decision, policy_reasons
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    timestamp,
                    timestamp,
                    request.tool,
                    evaluation.normalized_target,
                    json.dumps(request.arguments, sort_keys=True),
                    request.justification,
                    requester,
                    int(request.dry_run),
                    status.value,
                    evaluation.decision.value,
                    json.dumps(evaluation.reasons),
                ),
            )
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> JobRecord:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        return self._row_to_job(row)

    def list_jobs(self, limit: int = 100) -> list[JobRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_job(row) for row in rows]

    def update_job(self, job_id: str, **changes: Any) -> JobRecord:
        allowed = {"status", "approved_by", "approval_reason", "result", "error"}
        if not changes or not set(changes).issubset(allowed):
            raise ValueError("unsupported job update")
        serialized: dict[str, Any] = {}
        for key, value in changes.items():
            if key == "status" and isinstance(value, JobStatus):
                value = value.value
            if key == "result" and value is not None:
                value = json.dumps(value, sort_keys=True)
            serialized[key] = value
        serialized["updated_at"] = utc_now()
        assignments = ", ".join(f"{key} = ?" for key in serialized)
        values = [*serialized.values(), job_id]
        with self._connect() as connection:
            cursor = connection.execute(f"UPDATE jobs SET {assignments} WHERE id = ?", values)
            if cursor.rowcount != 1:
                raise KeyError(job_id)
        return self.get_job(job_id)

    def transition_job(
        self,
        job_id: str,
        expected: set[JobStatus],
        new_status: JobStatus,
        **changes: Any,
    ) -> JobRecord:
        allowed = {"approved_by", "approval_reason", "result", "error"}
        if not set(changes).issubset(allowed):
            raise ValueError("unsupported job transition update")
        serialized: dict[str, Any] = {"status": new_status.value, "updated_at": utc_now()}
        for key, value in changes.items():
            if key == "result" and value is not None:
                value = json.dumps(value, sort_keys=True)
            serialized[key] = value
        assignments = ", ".join(f"{key} = ?" for key in serialized)
        expected_values = sorted(status.value for status in expected)
        placeholders = ", ".join("?" for _ in expected_values)
        values = [*serialized.values(), job_id, *expected_values]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                f"UPDATE jobs SET {assignments} WHERE id = ? AND status IN ({placeholders})",
                values,
            )
            if cursor.rowcount != 1:
                exists = connection.execute("SELECT 1 FROM jobs WHERE id = ?", (job_id,)).fetchone()
                if exists is None:
                    raise KeyError(job_id)
                raise RuntimeError("job status changed before transition")
        return self.get_job(job_id)

    def append_audit(
        self,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        details: dict[str, Any] | None = None,
    ) -> AuditRecord:
        timestamp = utc_now()
        details = details or {}
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else "0" * 64
            canonical = json.dumps(
                {
                    "timestamp": timestamp,
                    "actor": actor,
                    "action": action,
                    "object_type": object_type,
                    "object_id": object_id,
                    "details": details,
                    "previous_hash": previous_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    timestamp, actor, action, object_type, object_id,
                    details, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    actor,
                    action,
                    object_type,
                    object_id,
                    json.dumps(details, sort_keys=True),
                    previous_hash,
                    event_hash,
                ),
            )
            sequence = int(cursor.lastrowid)
        return AuditRecord(
            sequence=sequence,
            timestamp=timestamp,
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            details=details,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    def list_audit(self, limit: int = 200) -> list[AuditRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_audit(row) for row in rows]

    def verify_audit_chain(self) -> bool:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY sequence ASC").fetchall()
        previous_hash = "0" * 64
        for row in rows:
            if row["previous_hash"] != previous_hash:
                return False
            canonical = json.dumps(
                {
                    "timestamp": row["timestamp"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "object_type": row["object_type"],
                    "object_id": row["object_id"],
                    "details": json.loads(row["details"]),
                    "previous_hash": row["previous_hash"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if expected != row["event_hash"]:
                return False
            previous_hash = row["event_hash"]
        return True

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> JobRecord:
        return JobRecord(
            id=row["id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            tool=row["tool"],
            target=row["target"],
            arguments=json.loads(row["arguments"]),
            justification=row["justification"],
            requester=row["requester"],
            dry_run=bool(row["dry_run"]),
            status=JobStatus(row["status"]),
            decision=Decision(row["decision"]),
            policy_reasons=json.loads(row["policy_reasons"]),
            approved_by=row["approved_by"],
            approval_reason=row["approval_reason"],
            result=json.loads(row["result"]) if row["result"] else None,
            error=row["error"],
        )

    @staticmethod
    def _row_to_audit(row: sqlite3.Row) -> AuditRecord:
        return AuditRecord(
            sequence=row["sequence"],
            timestamp=row["timestamp"],
            actor=row["actor"],
            action=row["action"],
            object_type=row["object_type"],
            object_id=row["object_id"],
            details=json.loads(row["details"]),
            previous_hash=row["previous_hash"],
            event_hash=row["event_hash"],
        )

