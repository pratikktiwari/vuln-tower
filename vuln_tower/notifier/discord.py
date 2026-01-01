"""
Discord webhook notifier.

Sends CVE notifications to Discord channels via webhooks.
"""

from typing import List
import requests
import time

from vuln_tower.core import StructuredLogger
from vuln_tower.models import CVE
from .base import Notifier


class DiscordNotifier(Notifier):
    """
    Sends CVE alerts to Discord via webhook.

    Format: Discord embed messages with CVE details.
    """

    def __init__(
        self, webhook_url: str, logger: StructuredLogger, rate_limit_delay: float = 1.0
    ):
        """
        Initialize Discord notifier.

        Args:
            webhook_url: Discord webhook URL
            logger: Structured logger instance
            rate_limit_delay: Delay in seconds between requests (default: 1.0)
        """
        self.webhook_url = webhook_url
        self.logger = logger
        self.rate_limit_delay = rate_limit_delay

    def send(self, cves: List[CVE]):
        """
        Send CVE notifications to Discord.

        Args:
            cves: List of CVEs to notify about
        """
        if not cves:
            return

        self.logger.info("Sending notifications to Discord", count=len(cves))

        for i, cve in enumerate(cves):
            try:
                retry_after = self._send_single(cve)

                # Rate limiting: always apply configured delay, add Retry-After on top if present
                if i < len(cves) - 1:  # Don't sleep after the last message
                    delay = self.rate_limit_delay + (retry_after if retry_after else 0)
                    self.logger.debug(f"Rate limiting: sleeping for {delay}s")
                    time.sleep(delay)
            except Exception as e:
                self.logger.error(
                    "Failed to send Discord notification",
                    cve_id=cve.cve_id,
                    error=str(e),
                )

    def _send_single(self, cve: CVE) -> float:
        """Send a single CVE notification.

        Returns:
            Retry-After delay in seconds if present in response headers, else None
        """
        embed = self._create_embed(cve)

        payload = {"embeds": [embed]}

        response = requests.post(self.webhook_url, json=payload, timeout=10)
        response.raise_for_status()

        # Check for Retry-After header
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                return None
        return None

    def _create_embed(self, cve: CVE) -> dict:
        """
        Create Discord embed for CVE.

        Args:
            cve: CVE to format

        Returns:
            Discord embed dictionary
        """
        # Determine color based on severity
        color_map = {
            "CRITICAL": 0xFF0000,  # Red
            "HIGH": 0xFF6600,  # Orange
            "MEDIUM": 0xFFCC00,  # Yellow
            "LOW": 0x00FF00,  # Green
        }
        color = color_map.get(cve.severity, 0x808080)  # Gray default

        # Build fields
        fields = []

        if cve.cvss_score:
            fields.append(
                {
                    "name": "CVSS Score",
                    "value": f"{cve.cvss_score}/10.0",
                    "inline": True,
                }
            )

        if cve.severity:
            fields.append({"name": "Severity", "value": cve.severity, "inline": True})

        if cve.attack_vector:
            fields.append(
                {"name": "Attack Vector", "value": cve.attack_vector, "inline": True}
            )

        if cve.affected_products:
            products = ", ".join(cve.affected_products[:5])
            if len(cve.affected_products) > 5:
                products += "..."
            fields.append(
                {"name": "Affected Products", "value": products, "inline": False}
            )

        # Add enriched summary if available
        description = cve.enriched_summary or cve.description
        if len(description) > 2000:
            description = description[:1997] + "..."

        embed = {
            "title": cve.cve_id,
            "description": description,
            "url": cve.nvd_url,
            "color": color,
            "fields": fields,
            "timestamp": cve.published_date.isoformat(),
        }

        # Add risk assessment if available
        if cve.risk_assessment:
            embed["fields"].append(
                {
                    "name": "Risk Assessment",
                    "value": cve.risk_assessment[:1024],
                    "inline": False,
                }
            )

        # Add recommended actions if available
        if cve.recommended_actions:
            embed["fields"].append(
                {
                    "name": "Recommended Actions",
                    "value": cve.recommended_actions[:1024],
                    "inline": False,
                }
            )

        return embed

    def get_notifier_name(self) -> str:
        return "DiscordNotifier"
