"""
Storage backends for CVE persistence.

Provides a unified interface across SQLite, PostgreSQL, and MySQL.
"""

from vuln_tower.core import Config
from .base import StorageBackend
from .sqlite import SQLiteStorage
from .postgres import PostgresStorage
from .mysql import MySQLStorage


def create_storage(config: Config) -> StorageBackend:
    """
    Factory function to create appropriate storage backend.

    Args:
        config: Application configuration

    Returns:
        Initialized StorageBackend instance

    Raises:
        ValueError: If database type is unsupported
    """
    db_config = config.database

    if db_config.db_type == "sqlite":
        storage = SQLiteStorage(db_config.db_name)
    elif db_config.db_type == "postgres":
        if not all([db_config.db_host, db_config.db_user, db_config.db_password]):
            raise ValueError("PostgreSQL requires DB_HOST, DB_USER, and DB_PASSWORD")
        storage = PostgresStorage(
            host=db_config.db_host,
            port=db_config.db_port or 5432,
            database=db_config.db_name,
            user=db_config.db_user,
            password=db_config.db_password,
        )
    elif db_config.db_type == "mysql":
        if not all([db_config.db_host, db_config.db_user, db_config.db_password]):
            raise ValueError("MySQL requires DB_HOST, DB_USER, and DB_PASSWORD")
        storage = MySQLStorage(
            host=db_config.db_host,
            port=db_config.db_port or 3306,
            database=db_config.db_name,
            user=db_config.db_user,
            password=db_config.db_password,
        )
    else:
        raise ValueError(f"Unsupported database type: {db_config.db_type}")

    storage.initialize()
    return storage


__all__ = [
    "StorageBackend",
    "SQLiteStorage",
    "PostgresStorage",
    "MySQLStorage",
    "create_storage",
]
