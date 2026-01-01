"""
Abstract notifier interface.

Defines the contract for sending CVE notifications to various channels.
"""

from abc import ABC, abstractmethod
from typing import List

from vuln_tower.models import CVE


class Notifier(ABC):
    """
    Abstract interface for notification channels.

    Implementations send formatted CVE alerts to specific platforms
    (Discord, Slack, Teams, email, etc.)
    """

    @abstractmethod
    def send(self, cves: List[CVE]):
        """
        Send CVE notifications to the channel.

        Args:
            cves: List of CVEs to notify about

        Raises:
            RuntimeError: If sending fails
        """
        pass

    @abstractmethod
    def get_notifier_name(self) -> str:
        """
        Get the name of this notifier for logging purposes.

        Returns:
            Notifier name
        """
        pass
