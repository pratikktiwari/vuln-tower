"""
PostgreSQL storage backend.

Implements storage using PostgreSQL for distributed deployments.
"""

from datetime import datetime
from typing import List, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None

from vuln_tower.models import CVE
from .base import StorageBackend


class PostgresStorage(StorageBackend):
    """
    PostgreSQL-based storage implementation.

    Suitable for production deployments with high availability requirements.
    """

    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        """
        Initialize PostgreSQL storage.

        Args:
            host: PostgreSQL server host
            port: PostgreSQL server port
            database: Database name
            user: Database user
            password: Database password
        """
        if psycopg2 is None:
            raise ImportError(
                "psycopg2 is required for PostgreSQL storage. "
                "Install with: pip install psycopg2-binary"
            )

        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.connection = None

    def initialize(self):
        """Connect to PostgreSQL and create schema."""
        self.connection = psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password,
        )

        cursor = self.connection.cursor()

        # Create processed_cves table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_cves (
                cve_id VARCHAR(50) PRIMARY KEY,
                published_date TIMESTAMP NOT NULL,
                severity VARCHAR(20),
                cvss_score DECIMAL(3,1),
                notified_at TIMESTAMP NOT NULL
            )
        """
        )

        # Create metadata table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key VARCHAR(255) PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL
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
        cursor.execute("SELECT 1 FROM processed_cves WHERE cve_id = %s", (cve_id,))
        return cursor.fetchone() is not None

    def mark_processed(self, cve: CVE):
        """Insert CVE into processed_cves table."""
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO processed_cves 
            (cve_id, published_date, severity, cvss_score, notified_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE
            SET published_date = EXCLUDED.published_date,
                severity = EXCLUDED.severity,
                cvss_score = EXCLUDED.cvss_score,
                notified_at = EXCLUDED.notified_at
        """,
            (
                cve.cve_id,
                cve.published_date,
                cve.severity,
                cve.cvss_score,
                datetime.utcnow(),
            ),
        )
        self.connection.commit()

    def get_processed_cves(self, limit: Optional[int] = None) -> List[str]:
        """Retrieve list of processed CVE IDs."""
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)

        query = "SELECT cve_id FROM processed_cves ORDER BY notified_at DESC"
        if limit:
            query += f" LIMIT {limit}"

        cursor.execute(query)
        return [row["cve_id"] for row in cursor.fetchall()]

    def get_metadata(self, key: str) -> Optional[str]:
        """Retrieve metadata value."""
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT value FROM meta WHERE key = %s", (key,))
        row = cursor.fetchone()
        return row["value"] if row else None

    def set_metadata(self, key: str, value: str):
        """Store metadata key-value pair."""
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO meta (key, value, updated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value,
                updated_at = EXCLUDED.updated_at
        """,
            (key, value, datetime.utcnow()),
        )
        self.connection.commit()

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
