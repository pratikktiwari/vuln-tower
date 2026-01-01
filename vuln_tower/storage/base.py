"""
Abstract storage interface.

Defines the contract for CVE persistence across different database backends.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional

from vuln_tower.models import CVE


class StorageBackend(ABC):
    """
    Abstract interface for CVE storage.

    Implementations must handle:
    - Schema creation
    - CVE persistence
    - Deduplication
    - Metadata storage
    """

    @abstractmethod
    def initialize(self):
        """
        Initialize storage backend.

        Create tables/schema if they don't exist.
        """
        pass

    @abstractmethod
    def is_processed(self, cve_id: str) -> bool:
        """
        Check if a CVE has already been processed.

        Args:
            cve_id: CVE identifier

        Returns:
            True if CVE was previously processed
        """
        pass

    @abstractmethod
    def mark_processed(self, cve: CVE):
        """
        Mark a CVE as processed.

        Args:
            cve: CVE object to persist
        """
        pass

    @abstractmethod
    def get_processed_cves(self, limit: Optional[int] = None) -> List[str]:
        """
        Get list of processed CVE IDs.

        Args:
            limit: Maximum number of IDs to return

        Returns:
            List of CVE IDs
        """
        pass

    @abstractmethod
    def get_metadata(self, key: str) -> Optional[str]:
        """
        Retrieve metadata value by key.

        Args:
            key: Metadata key

        Returns:
            Value if exists, None otherwise
        """
        pass

    @abstractmethod
    def set_metadata(self, key: str, value: str):
        """
        Store metadata key-value pair.

        Args:
            key: Metadata key
            value: Metadata value
        """
        pass

    @abstractmethod
    def close(self):
        """Close storage backend connections."""
        pass
