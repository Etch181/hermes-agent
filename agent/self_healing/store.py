"""Dedicated durable incident ledger; never shares operational databases."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.redact import redact_sensitive_text

MAX_PERSISTED_MUTATIONS = 3


def _redact(value: Any) -> Any:
    """Redact every value before it crosses this durable-storage boundary."""
    if isinstance(value, dict):
        return {str(key): _redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_sensitive_text(str(value), force=True, redact_url_credentials=True)


def _signature(workspace: str, failure: str, classification: str) -> str:
    """Stable repair-scope signature that prevents budget reset via signature churn.

    Uses:
    - workspace (immutable for a given repo)
    - failure classification kind (from classify_failure - bounded, not caller-controlled)
    - normalized file context from failure (extracted paths/filenames, bounded)

    Does NOT use:
    - raw failure text (caller-controlled)
    - incident ID (mutable)
    - arbitrary signature text (mutable)
    """
    # Extract bounded file context from failure (filenames, paths) - max 3, sorted
    import re
    file_refs = re.findall(r'[\w/.-]+\.(?:py|js|ts|json|yaml|yml|toml|ini|cfg|conf|txt|md|sh|bash|zsh|fish)', failure)
    file_context = "|".join(sorted(set(file_refs))[:3]) if file_refs else "no-files"
    
    # Normalized classification kind (bounded enum from classifier)
    kind = classification if classification in {"sensitive", "system", "environment", "code"} else "code"
    
    return hashlib.sha256(f"{workspace}\0{kind}\0{file_context}".encode()).hexdigest()


class IncidentStore:
    def __init__(self, path: Path | None = None) -> None:
        if path is None:
            from hermes_constants import get_hermes_home
            path = get_hermes_home() / "self_healing_incidents.db"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, workspace TEXT NOT NULL, failure TEXT NOT NULL, signature TEXT NOT NULL, risk TEXT NOT NULL, state TEXT NOT NULL, mutations INTEGER NOT NULL DEFAULT 0 CHECK(mutations >= 0 AND mutations <= 3), payload TEXT NOT NULL DEFAULT '{}')"
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
            if "signature" not in columns:
                conn.execute("ALTER TABLE incidents ADD COLUMN signature TEXT")
                conn.execute("UPDATE incidents SET signature = id WHERE signature IS NULL")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS incidents_signature_unique ON incidents(signature)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_or_get(self, *, workspace: str, failure: str, risk: str, payload: dict[str, Any] | None = None, classification: str = "code") -> str:
        """Deduplicate equivalent incidents and retain their persisted budget."""
        signature = _signature(workspace, failure, classification)
        safe_failure = _redact(failure)[:2000]
        safe_payload = _redact(payload or {})
        now = self._now()
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM incidents WHERE signature = ?", (signature,)).fetchone()
            if row is not None:
                return str(row["id"])
            incident_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO incidents(id, created_at, updated_at, workspace, failure, signature, risk, state, payload) VALUES (?, ?, ?, ?, ?, ?, ?, 'detected', ?)",
                (incident_id, now, now, workspace, safe_failure, signature, risk, json.dumps(safe_payload)),
            )
        return incident_id

    def create(self, *, workspace: str, failure: str, risk: str, payload: dict[str, Any] | None = None, classification: str = "code") -> str:
        return self.create_or_get(workspace=workspace, failure=failure, risk=risk, payload=payload, classification=classification)

    def reserve_mutation(self, incident_id: str) -> bool:
        """Atomically reserve one of at most three durable mutation attempts."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE incidents SET mutations = mutations + 1, updated_at = ? WHERE id = ? AND mutations < ?",
                (self._now(), incident_id, MAX_PERSISTED_MUTATIONS),
            )
            return cursor.rowcount == 1

    def update(self, incident_id: str, *, state: str, mutations: int | None = None, payload: dict[str, Any] | None = None) -> None:
        with self._connect() as conn:
            fields, values = ["state = ?", "updated_at = ?"], [state, self._now()]
            if mutations is not None:
                # Never allow callers to bypass the persistent mutation ceiling.
                fields.append("mutations = ?")
                values.append(min(MAX_PERSISTED_MUTATIONS, max(0, int(mutations))))
            if payload is not None:
                fields.append("payload = ?")
                values.append(json.dumps(_redact(payload)))
            values.append(incident_id)
            conn.execute(f"UPDATE incidents SET {', '.join(fields)} WHERE id = ?", values)

    def mutation_count(self, incident_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT mutations FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return int(row["mutations"]) if row is not None else 0

    def get(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._row_to_dict(row)

    def list(self, *, workspace: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Read recent redacted incident metadata for ``hermes heal status``."""
        limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            if workspace:
                rows = conn.execute(
                    "SELECT * FROM incidents WHERE workspace = ? ORDER BY updated_at DESC LIMIT ?",
                    (workspace, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [item for row in rows if (item := self._row_to_dict(row)) is not None]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result
