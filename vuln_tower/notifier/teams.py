"""
Microsoft Teams webhook notifier.

Sends CVE notifications to Teams channels via webhooks.
"""

from typing import List
import requests
import time

from vuln_tower.core import StructuredLogger
from vuln_tower.models import CVE
from .base import Notifier


class TeamsNotifier(Notifier):
    """
    Sends CVE alerts to Microsoft Teams via webhook.

    Format: Adaptive Cards for rich formatting.
    """

    def __init__(
        self, webhook_url: str, logger: StructuredLogger, rate_limit_delay: float = 1.0
    ):
        """
        Initialize Teams notifier.

        Args:
            webhook_url: Teams webhook URL
            logger: Structured logger instance
            rate_limit_delay: Delay in seconds between requests (default: 1.0)
        """
        self.webhook_url = webhook_url
        self.logger = logger
        self.rate_limit_delay = rate_limit_delay

    def send(self, cves: List[CVE]):
        """
        Send CVE notifications to Teams.

        Args:
            cves: List of CVEs to notify about
        """
        if not cves:
            return

        self.logger.info("Sending notifications to Teams", count=len(cves))

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
                    "Failed to send Teams notification", cve_id=cve.cve_id, error=str(e)
                )

    def _send_single(self, cve: CVE) -> float:
        """Send a single CVE notification.

        Returns:
            Retry-After delay in seconds if present in response headers, else None
        """
        card = self._create_card(cve)

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        }

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

    def _create_card(self, cve: CVE) -> dict:
        """
        Create Teams Adaptive Card for CVE.

        Args:
            cve: CVE to format

        Returns:
            Adaptive Card dictionary
        """
        # Determine color based on severity
        color_map = {
            "CRITICAL": "attention",
            "HIGH": "warning",
            "MEDIUM": "good",
            "LOW": "default",
        }
        color = color_map.get(cve.severity, "default")

        # Build card body
        body = []

        # Title
        body.append(
            {
                "type": "TextBlock",
                "text": cve.cve_id,
                "weight": "bolder",
                "size": "large",
                "color": color,
            }
        )

        # Description
        description = cve.enriched_summary or cve.description
        if len(description) > 1500:
            description = description[:1497] + "..."

        body.append(
            {
                "type": "TextBlock",
                "text": description,
                "wrap": True,
                "spacing": "medium",
            }
        )

        # Metadata fact set
        facts = []

        if cve.cvss_score:
            facts.append({"title": "CVSS Score", "value": f"{cve.cvss_score}/10.0"})

        if cve.severity:
            facts.append({"title": "Severity", "value": cve.severity})

        if cve.attack_vector:
            facts.append({"title": "Attack Vector", "value": cve.attack_vector})

        if cve.published_date:
            facts.append(
                {"title": "Published", "value": cve.published_date.strftime("%Y-%m-%d")}
            )

        if facts:
            body.append({"type": "FactSet", "facts": facts, "spacing": "medium"})

        # Affected products
        if cve.affected_products:
            products = ", ".join(cve.affected_products[:8])
            if len(cve.affected_products) > 8:
                products += "..."

            body.append(
                {
                    "type": "TextBlock",
                    "text": f"**Affected Products:** {products}",
                    "wrap": True,
                    "spacing": "medium",
                }
            )

        # Risk assessment if available
        if cve.risk_assessment:
            body.append(
                {
                    "type": "TextBlock",
                    "text": f"**Risk Assessment:** {cve.risk_assessment[:1000]}",
                    "wrap": True,
                    "spacing": "medium",
                }
            )

        # Recommended actions if available
        if cve.recommended_actions:
            body.append(
                {
                    "type": "TextBlock",
                    "text": f"**Recommended Actions:** {cve.recommended_actions[:1000]}",
                    "wrap": True,
                    "spacing": "medium",
                }
            )

        # Card structure
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": body,
            "actions": [
                {"type": "Action.OpenUrl", "title": "View on NVD", "url": cve.nvd_url}
            ],
        }

        return card

    def get_notifier_name(self) -> str:
        return "TeamsNotifier"
