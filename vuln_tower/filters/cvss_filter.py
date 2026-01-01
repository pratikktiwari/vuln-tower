"""
CVSS score-based filter.

Filters CVEs based on minimum CVSS severity score.
"""

from vuln_tower.models import CVE
from .base import CVEFilter


class CVSSFilter(CVEFilter):
    """
    Filter CVEs by minimum CVSS score.

    CVEs with scores below the threshold are excluded.
    A threshold of 0.0 allows all CVEs.
    """

    def __init__(self, min_score: float):
        """
        Initialize CVSS filter.

        Args:
            min_score: Minimum CVSS base score (0.0 - 10.0)
        """
        if not 0.0 <= min_score <= 10.0:
            raise ValueError("CVSS score must be between 0.0 and 10.0")

        self.min_score = min_score

    def should_notify(self, cve: CVE) -> bool:
        """
        Check if CVE meets minimum CVSS score threshold.

        Args:
            cve: CVE to evaluate

        Returns:
            True if CVE score >= min_score, or if score is unavailable
        """
        # If no score is available, default to allowing the CVE
        if cve.cvss_score is None:
            return self.min_score == 0.0

        return cve.cvss_score >= self.min_score

    def get_filter_name(self) -> str:
        return f"CVSSFilter(min_score={self.min_score})"
