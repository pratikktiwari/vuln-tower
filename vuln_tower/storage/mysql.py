"""
MySQL storage backend.

Implements storage using MySQL for deployments requiring MySQL compatibility.
"""

from datetime import datetime
from typing import List, Optional

try:
    import mysql.connector
except ImportError:
    mysql = None

from vuln_tower.models import CVE
from .base import StorageBackend


class MySQLStorage(StorageBackend):
    """
    MySQL-based storage implementation.

    Compatible with MySQL and MariaDB.
    """

    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        """
        Initialize MySQL storage.

        Args:
            host: MySQL server host
            port: MySQL server port
            database: Database name
            user: Database user
            password: Database password
        """
        if mysql is None:
            raise ImportError(
                "mysql-connector-python is required for MySQL storage. "
                "Install with: pip install mysql-connector-python"
            )

        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.connection = None

    def initialize(self):
        """Connect to MySQL and create schema."""
        self.connection = mysql.connector.connect(
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
                published_date DATETIME NOT NULL,
                severity VARCHAR(20),
                cvss_score DECIMAL(3,1),
                notified_at DATETIME NOT NULL
            )
        """
        )

        # Create metadata table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                `key` VARCHAR(255) PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at DATETIME NOT NULL
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
            ON DUPLICATE KEY UPDATE
                published_date = VALUES(published_date),
                severity = VALUES(severity),
                cvss_score = VALUES(cvss_score),
                notified_at = VALUES(notified_at)
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
        cursor = self.connection.cursor(dictionary=True)

        query = "SELECT cve_id FROM processed_cves ORDER BY notified_at DESC"
        if limit:
            query += f" LIMIT {limit}"

        cursor.execute(query)
        return [row["cve_id"] for row in cursor.fetchall()]

    def get_metadata(self, key: str) -> Optional[str]:
        """Retrieve metadata value."""
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute("SELECT value FROM meta WHERE `key` = %s", (key,))
        row = cursor.fetchone()
        return row["value"] if row else None

    def set_metadata(self, key: str, value: str):
        """Store metadata key-value pair."""
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO meta (`key`, value, updated_at)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
                value = VALUES(value),
                updated_at = VALUES(updated_at)
        """,
            (key, value, datetime.utcnow()),
        )
        self.connection.commit()

    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
