"""
Abstract filter interface.

Defines the contract for CVE filtering implementations.
"""

from abc import ABC, abstractmethod

from vuln_tower.models import CVE


class CVEFilter(ABC):
    """
    Abstract interface for CVE filtering.

    Filters determine whether a CVE should be processed and sent
    to notification channels.
    """

    @abstractmethod
    def should_notify(self, cve: CVE) -> bool:
        """
        Determine if a CVE matches filter criteria.

        Args:
            cve: CVE to evaluate

        Returns:
            True if CVE passes the filter and should be notified
        """
        pass

    @abstractmethod
    def get_filter_name(self) -> str:
        """
        Get the name of this filter for logging purposes.

        Returns:
            Filter name
        """
        pass
