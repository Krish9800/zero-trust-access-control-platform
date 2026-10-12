"""SQLite WAL Persistence Engine.

Provides thread-safe persistence for policies, access evaluation audit logs,
active sessions, and security events. Enforces WAL (Write-Ahead Logging) mode,
foreign keys, and strict query parameterization against SQL injection.
"""

import json
import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zero_trust.config.settings import Settings, get_settings
from zero_trust.models.enums import (
    NetworkZone,
    PolicyEffect,
    SensitivityLevel,
)
from zero_trust.models.schemas import AccessEvaluationResult, ZeroTrustPolicy
from zero_trust.sessions.manager import ActiveSession


class DatabaseManager:
    """Manages SQLite connection pooling and transactional operations in WAL mode."""

    def __init__(self, db_path: Path | None = None, settings: Settings | None = None) -> None:
        """Initialize DatabaseManager with database file path and settings."""
        self._settings = settings or get_settings()
        self._db_path = db_path or self._settings.db_path
        # Ensure parent directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize_schema()

    def get_connection(self) -> sqlite3.Connection:
        """Create and configure a new SQLite connection with WAL mode enabled."""
        conn = sqlite3.connect(
            str(self._db_path),
            timeout=self._settings.db_timeout_seconds,
        )
        conn.row_factory = sqlite3.Row
        # Configure SQLite pragmas for high performance and durability
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding a transactional SQLite connection."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        """Execute DDL schema to prepare database tables and indexes."""
        schema_file = Path(__file__).parent / "schema.sql"
        if not schema_file.exists():
            raise FileNotFoundError(f"Schema file not found at {schema_file}")

        ddl = schema_file.read_text(encoding="utf-8")
        with self.transaction() as conn:
            conn.executescript(ddl)

    # ---------------- Policies ----------------

    def save_policy(self, policy: ZeroTrustPolicy) -> None:
        """Insert or replace a ZeroTrustPolicy."""
        now = datetime.now(UTC).isoformat()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO policies (
                    policy_id, name, description, effect, priority, min_trust_score,
                    allowed_roles, allowed_departments, max_sensitivity,
                    require_encryption, require_edr, conditions, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    policy.policy_id,
                    policy.name,
                    policy.description,
                    policy.effect.value,
                    policy.priority,
                    policy.min_trust_score,
                    json.dumps(policy.allowed_roles),
                    json.dumps(policy.allowed_departments),
                    policy.max_sensitivity.value,
                    1 if policy.require_encryption else 0,
                    1 if policy.require_edr else 0,
                    json.dumps(policy.conditions),
                    now,
                    now,
                ),
            )

    def get_policy(self, policy_id: str) -> ZeroTrustPolicy | None:
        """Retrieve policy by policy_id."""
        with self.transaction() as conn:
            cursor = conn.execute("SELECT * FROM policies WHERE policy_id = ?;", (policy_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_policy(row)

    def list_policies(self) -> list[ZeroTrustPolicy]:
        """List all registered policies sorted by priority ascending."""
        with self.transaction() as conn:
            cursor = conn.execute("SELECT * FROM policies ORDER BY priority ASC, policy_id ASC;")
            return [self._row_to_policy(r) for r in cursor.fetchall()]

    def delete_policy(self, policy_id: str) -> bool:
        """Delete policy by policy_id."""
        with self.transaction() as conn:
            cursor = conn.execute("DELETE FROM policies WHERE policy_id = ?;", (policy_id,))
            return cursor.rowcount > 0

    def _row_to_policy(self, row: sqlite3.Row) -> ZeroTrustPolicy:
        """Convert a sqlite3.Row to ZeroTrustPolicy model."""
        return ZeroTrustPolicy(
            policy_id=row["policy_id"],
            name=row["name"],
            description=row["description"],
            effect=PolicyEffect(row["effect"]),
            priority=row["priority"],
            min_trust_score=float(row["min_trust_score"]),
            allowed_roles=json.loads(row["allowed_roles"]),
            allowed_departments=json.loads(row["allowed_departments"]),
            max_sensitivity=SensitivityLevel(row["max_sensitivity"]),
            require_encryption=bool(row["require_encryption"]),
            require_edr=bool(row["require_edr"]),
            conditions=json.loads(row["conditions"]),
        )

    # ---------------- Access Evaluations Audit Log ----------------

    def record_evaluation(
        self,
        evaluation: AccessEvaluationResult,
        subject_id: str,
        device_id: str,
        resource_id: str,
    ) -> None:
        """Append an access evaluation audit entry."""
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO access_evaluations (
                    evaluation_id, request_id, subject_id, device_id, resource_id,
                    decision, total_trust_score, matched_policy_id, reasons, evaluated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    evaluation.evaluation_id,
                    evaluation.request_id,
                    subject_id,
                    device_id,
                    resource_id,
                    evaluation.decision.value,
                    evaluation.trust_score.total_score,
                    evaluation.matched_policy_id,
                    json.dumps(evaluation.reasons),
                    evaluation.evaluated_at.isoformat(),
                ),
            )

    def list_evaluations(self, limit: int = 100) -> list[dict[str, Any]]:
        """List recent access evaluation audit events."""
        with self.transaction() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM access_evaluations
                ORDER BY evaluated_at DESC
                LIMIT ?;
                """,
                (limit,),
            )
            results: list[dict[str, Any]] = []
            for r in cursor.fetchall():
                results.append(
                    {
                        "evaluation_id": r["evaluation_id"],
                        "request_id": r["request_id"],
                        "subject_id": r["subject_id"],
                        "device_id": r["device_id"],
                        "resource_id": r["resource_id"],
                        "decision": r["decision"],
                        "total_trust_score": float(r["total_trust_score"]),
                        "matched_policy_id": r["matched_policy_id"],
                        "reasons": json.loads(r["reasons"]),
                        "evaluated_at": r["evaluated_at"],
                    }
                )
            return results

    # ---------------- Active Sessions ----------------

    def save_session(self, session: ActiveSession) -> None:
        """Insert or update an active session record."""
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO active_sessions (
                    session_id, subject_id, device_id, device_fingerprint_hash,
                    resource_id, session_token, ip_address, network_zone,
                    is_revoked, revocation_reason, created_at, last_verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    session.session_id,
                    session.subject_id,
                    session.device_id,
                    session.device_fingerprint_hash,
                    session.resource_id,
                    session.session_token,
                    session.ip_address,
                    session.network_zone.value,
                    1 if session.is_revoked else 0,
                    session.revocation_reason,
                    session.created_at.isoformat(),
                    session.last_verified_at.isoformat(),
                ),
            )

    def get_session(self, session_id: str) -> ActiveSession | None:
        """Retrieve an active session by session_id."""
        with self.transaction() as conn:
            cursor = conn.execute(
                "SELECT * FROM active_sessions WHERE session_id = ?;", (session_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_session(row)

    def list_sessions(self, active_only: bool = True) -> list[ActiveSession]:
        """List stored sessions."""
        query = "SELECT * FROM active_sessions"
        if active_only:
            query += " WHERE is_revoked = 0"
        query += " ORDER BY created_at DESC;"

        with self.transaction() as conn:
            cursor = conn.execute(query)
            return [self._row_to_session(r) for r in cursor.fetchall()]

    def _row_to_session(self, row: sqlite3.Row) -> ActiveSession:
        """Convert a sqlite3.Row to ActiveSession model."""
        return ActiveSession(
            session_id=row["session_id"],
            subject_id=row["subject_id"],
            device_id=row["device_id"],
            device_fingerprint_hash=row["device_fingerprint_hash"],
            resource_id=row["resource_id"],
            session_token=row["session_token"],
            ip_address=row["ip_address"],
            network_zone=NetworkZone(row["network_zone"]),
            is_revoked=bool(row["is_revoked"]),
            revocation_reason=row["revocation_reason"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_verified_at=datetime.fromisoformat(row["last_verified_at"]),
        )

    # ---------------- Audit Events ----------------

    def log_audit_event(
        self,
        event_type: str,
        actor_id: str,
        target_id: str,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Append a generic security audit event."""
        event_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, event_type, actor_id, target_id, details, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    event_type,
                    actor_id,
                    target_id,
                    json.dumps(details or {}),
                    now,
                ),
            )
        return event_id
