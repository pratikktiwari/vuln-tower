"""
Abstract CVE fetcher interface.

Defines the contract for retrieving CVEs from external sources.
"""

from abc import ABC, abstractmethod
from typing import List

from vuln_tower.models import CVE


class CVEFetcher(ABC):
    """
    Abstract interface for CVE data sources.

    Implementations fetch CVEs from various sources (NVD, GitHub Security, etc.)
    and normalize them to the internal CVE domain model.
    """

    @abstractmethod
    def fetch(self) -> List[CVE]:
        """
        Fetch CVEs from the data source.

        Returns:
            List of CVE objects

        Raises:
            RuntimeError: If fetching fails
        """
        pass
