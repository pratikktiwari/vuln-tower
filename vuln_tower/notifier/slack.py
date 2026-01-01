"""
Slack webhook notifier.

Sends CVE notifications to Slack channels via webhooks.
"""

from typing import List
import requests
import time

from vuln_tower.core import StructuredLogger
from vuln_tower.models import CVE
from .base import Notifier


class SlackNotifier(Notifier):
    """
    Sends CVE alerts to Slack via webhook.

    Format: Slack block kit messages with CVE details.
    """

    def __init__(
        self, webhook_url: str, logger: StructuredLogger, rate_limit_delay: float = 1.0
    ):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL
            logger: Structured logger instance
            rate_limit_delay: Delay in seconds between requests (default: 1.0)
        """
        self.webhook_url = webhook_url
        self.logger = logger
        self.rate_limit_delay = rate_limit_delay

    def send(self, cves: List[CVE]):
        """
        Send CVE notifications to Slack.

        Args:
            cves: List of CVEs to notify about
        """
        if not cves:
            return

        self.logger.info("Sending notifications to Slack", count=len(cves))

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
                    "Failed to send Slack notification", cve_id=cve.cve_id, error=str(e)
                )

    def _send_single(self, cve: CVE) -> float:
        """Send a single CVE notification.

        Returns:
            Retry-After delay in seconds if present in response headers, else None
        """
        blocks = self._create_blocks(cve)

        payload = {"blocks": blocks}

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

    def _create_blocks(self, cve: CVE) -> List[dict]:
        """
        Create Slack blocks for CVE.

        Args:
            cve: CVE to format

        Returns:
            List of Slack block dictionaries
        """
        blocks = []

        # Header with CVE ID
        severity_emoji = {
            "CRITICAL": ":red_circle:",
            "HIGH": ":large_orange_circle:",
            "MEDIUM": ":large_yellow_circle:",
            "LOW": ":large_green_circle:",
        }
        emoji = severity_emoji.get(cve.severity, ":white_circle:")

        blocks.append(
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {cve.cve_id}"},
            }
        )

        # Description
        description = cve.enriched_summary or cve.description
        if len(description) > 3000:
            description = description[:2997] + "..."

        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": description}}
        )

        # Metadata fields
        fields = []

        if cve.cvss_score:
            fields.append(
                {"type": "mrkdwn", "text": f"*CVSS Score:*\n{cve.cvss_score}/10.0"}
            )

        if cve.severity:
            fields.append({"type": "mrkdwn", "text": f"*Severity:*\n{cve.severity}"})

        if cve.attack_vector:
            fields.append(
                {"type": "mrkdwn", "text": f"*Attack Vector:*\n{cve.attack_vector}"}
            )

        if cve.published_date:
            fields.append(
                {
                    "type": "mrkdwn",
                    "text": f"*Published:*\n{cve.published_date.strftime('%Y-%m-%d')}",
                }
            )

        if fields:
            blocks.append({"type": "section", "fields": fields})

        # Affected products
        if cve.affected_products:
            products = ", ".join(cve.affected_products[:10])
            if len(cve.affected_products) > 10:
                products += "..."

            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Affected Products:*\n{products}",
                    },
                }
            )

        # Risk assessment if available
        if cve.risk_assessment:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Risk Assessment:*\n{cve.risk_assessment[:3000]}",
                    },
                }
            )

        # Recommended actions if available
        if cve.recommended_actions:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Recommended Actions:*\n{cve.recommended_actions[:3000]}",
                    },
                }
            )

        # Link to NVD
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"<{cve.nvd_url}|View on NVD>"},
            }
        )

        # Divider
        blocks.append({"type": "divider"})

        return blocks

    def get_notifier_name(self) -> str:
        return "SlackNotifier"
