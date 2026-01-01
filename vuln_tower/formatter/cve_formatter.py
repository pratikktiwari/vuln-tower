"""
CVE formatter for human-readable output.

Provides consistent formatting across different notification channels.
"""

from typing import List
from vuln_tower.models import CVE


class CVEFormatter:
    """
    Formats CVE data for display.

    Provides utility methods for creating human-readable summaries,
    truncating long text, and formatting metadata.
    """

    @staticmethod
    def format_summary(cve: CVE, max_length: int = 500) -> str:
        """
        Create a concise summary of a CVE.

        Args:
            cve: CVE to summarize
            max_length: Maximum length of summary

        Returns:
            Formatted summary string
        """
        parts = [f"CVE: {cve.cve_id}"]

        if cve.severity:
            parts.append(f"Severity: {cve.severity}")

        if cve.cvss_score:
            parts.append(f"CVSS: {cve.cvss_score}/10.0")

        description = cve.enriched_summary or cve.description
        if len(description) > max_length:
            description = description[: max_length - 3] + "..."

        parts.append(description)

        return " | ".join(parts)

    @staticmethod
    def format_list(cves: List[CVE]) -> str:
        """
        Format a list of CVEs as plain text.

        Args:
            cves: List of CVEs to format

        Returns:
            Multi-line formatted string
        """
        if not cves:
            return "No CVEs to display"

        lines = [f"Found {len(cves)} CVE(s):\n"]

        for cve in cves:
            lines.append(f"- {CVEFormatter.format_summary(cve, max_length=200)}")

        return "\n".join(lines)

    @staticmethod
    def truncate(text: str, max_length: int, suffix: str = "...") -> str:
        """
        Truncate text to maximum length.

        Args:
            text: Text to truncate
            max_length: Maximum length
            suffix: Suffix to add if truncated

        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text

        return text[: max_length - len(suffix)] + suffix
