"""
Abstract pipeline step interface.

Defines the contract for middleware pipeline steps that can
enrich or transform CVE data.
"""

from abc import ABC, abstractmethod

from vuln_tower.models import CVE


class PipelineStep(ABC):
    """
    Abstract interface for pipeline middleware steps.

    Pipeline steps receive a CVE, perform enrichment or transformation,
    and return the potentially modified CVE.
    """

    @abstractmethod
    def process(self, cve: CVE) -> CVE:
        """
        Process a CVE through this pipeline step.

        Args:
            cve: CVE to process

        Returns:
            Processed CVE (may be modified)

        Raises:
            Exception: If processing fails (should be caught by pipeline)
        """
        pass

    @abstractmethod
    def get_step_name(self) -> str:
        """
        Get the name of this step for logging purposes.

        Returns:
            Step name
        """
        pass
