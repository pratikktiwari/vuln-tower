"""
SQLite storage backend.

Implements storage using SQLite, suitable for single-node deployments,
local development, and CI environments.
"""

import sqlite3
from datetime import datetime
from typing import List, Optional

from vuln_tower.models import CVE
from .base import StorageBackend


class SQLiteStorage(StorageBackend):
    """
    SQLite-based storage implementation.

    Uses a local SQLite database file for persistence.
    """

    def __init__(self, db_path: str):
        """
        Initialize SQLite storage.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None

    def initialize(self):
        """Create database schema if it doesn't exist."""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row

        cursor = self.connection.cursor()

        # Create processed_cves table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_cves (
                cve_id TEXT PRIMARY KEY,
                published_date TEXT NOT NULL,
                severity TEXT,
                cvss_score REAL,
                notified_at TEXT NOT NULL
            )
        """
        )

        # Create metadata table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )

        # Create indexes
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_notified_at 
            ON processed_cves(notified_at)
        """
        )

        self.connection.commit()

    def is_processed(self, cve_id: str) -> bool:
        """Check if CVE exists in processed_cves table."""
        cursor = self.connection.cursor()
        cursor.execute("SELECT 1 FROM processed_cves WHERE cve_id = ?", (cve_id,))
        return cursor.fetchone() is not None

    def mark_processed(self, cve: CVE):
        """Insert CVE into processed_cves table."""
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO processed_cves 
            (cve_id, published_date, severity, cvss_score, notified_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                cve.cve_id,
                cve.published_date.isoformat(),
                cve.severity,
                cve.cvss_score,
                datetime.utcnow().isoformat(),
            ),
        )
        self.connection.commit()

    def get_processed_cves(self, limit: Optional[int] = None) -> List[str]:
        """Retrieve list of processed CVE IDs."""
        cursor = self.connection.cursor()

        query = "SELECT cve_id FROM processed_cves ORDER BY notified_at DESC"
        if limit:
            query += f" LIMIT {limit}"

        cursor.execute(query)
        return [row["cve_id"] for row in cursor.fetchall()]

    def get_metadata(self, key: str) -> Optional[str]:
        """Retrieve metadata value."""
        cursor = self.connection.cursor()
        cursor.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else None

    def set_metadata(self, key: str, value: str):
        """Store metadata key-value pair."""
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO meta (key, value, updated_at)
            VALUES (?, ?, ?)
        """,
            (key, value, datetime.utcnow().isoformat()),
        )
        self.connection.commit()

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
