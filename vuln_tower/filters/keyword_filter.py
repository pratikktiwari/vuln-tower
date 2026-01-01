"""
Keyword-based filter.

Filters CVEs based on keywords appearing in the description.
"""

from typing import List

from vuln_tower.models import CVE
from .base import CVEFilter


class KeywordFilter(CVEFilter):
    """
    Filter CVEs by keywords in description.

    If keywords list is empty, all CVEs pass.
    If keywords are provided, CVE description must contain at least one.
    """

    def __init__(self, keywords: List[str]):
        """
        Initialize keyword filter.

        Args:
            keywords: List of keywords to match (case-insensitive)
        """
        self.keywords = [k.lower() for k in keywords]

    def should_notify(self, cve: CVE) -> bool:
        """
        Check if CVE description contains any of the keywords.

        Args:
            cve: CVE to evaluate

        Returns:
            True if any keyword is found, or if keyword list is empty
        """
        if not self.keywords:
            return True

        return cve.matches_keywords(self.keywords)

    def get_filter_name(self) -> str:
        keyword_str = ", ".join(self.keywords[:3])
        if len(self.keywords) > 3:
            keyword_str += "..."
        return f"KeywordFilter(keywords=[{keyword_str}])"
