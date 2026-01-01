"""
Telegram Bot API notifier.

Sends CVE notifications to Telegram chats via Bot API.
"""

from typing import List
import requests
import time

from vuln_tower.core import StructuredLogger
from vuln_tower.models import CVE
from .base import Notifier


class TelegramNotifier(Notifier):
    """
    Sends CVE alerts to Telegram via Bot API.

    Format: Formatted text messages with CVE details using Markdown.
    """

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        logger: StructuredLogger,
        rate_limit_delay: float = 1.0,
    ):
        """
        Initialize Telegram notifier.

        Args:
            bot_token: Telegram Bot API token
            chat_id: Telegram chat ID (can be user ID, group ID, or channel username)
            logger: Structured logger instance
            rate_limit_delay: Delay in seconds between requests (default: 1.0)
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.logger = logger
        self.rate_limit_delay = rate_limit_delay
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    def send(self, cves: List[CVE]):
        """
        Send CVE notifications to Telegram.

        Args:
            cves: List of CVEs to notify about
        """
        if not cves:
            return

        self.logger.info("Sending notifications to Telegram", count=len(cves))

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
                    "Failed to send Telegram notification",
                    cve_id=cve.cve_id,
                    error=str(e),
                )

    def _send_single(self, cve: CVE) -> float:
        """Send a single CVE notification.

        Returns:
            Retry-After delay in seconds if present in response headers, else None
        """
        message = self._create_message(cve)

        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": False,
        }

        response = requests.post(self.api_url, json=payload, timeout=10)

        if response.status_code != 200:
            self.logger.error(
                "Telegram API error",
                status_code=response.status_code,
                response=response.text,
            )
            raise Exception(f"Telegram API returned {response.status_code}")

        self.logger.debug("Telegram notification sent", cve_id=cve.cve_id)

        # Check for Retry-After header
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                return None
        return None

    def _create_message(self, cve: CVE) -> str:
        """
        Create a formatted Telegram message for a CVE.

        Args:
            cve: CVE to format

        Returns:
            Formatted message string in MarkdownV2 format
        """

        # Escape special characters for MarkdownV2
        def escape(text: str) -> str:
            if not text:
                return ""
            # Escape special characters: _ * [ ] ( ) ~ ` > # + - = | { } . !
            special_chars = [
                "_",
                "*",
                "[",
                "]",
                "(",
                ")",
                "~",
                "`",
                ">",
                "#",
                "+",
                "-",
                "=",
                "|",
                "{",
                "}",
                ".",
                "!",
            ]
            for char in special_chars:
                text = text.replace(char, f"\\{char}")
            return text

        # Severity emoji
        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        emoji = severity_emoji.get(cve.severity or "MEDIUM", "⚪")

        # Build message
        lines = [f"{emoji} *{escape(cve.cve_id)}*", ""]

        # Severity and CVSS
        if cve.severity:
            lines.append(f"*Severity:* {escape(cve.severity)}")

        if cve.cvss_score is not None:
            lines.append(f"*CVSS Score:* {escape(str(cve.cvss_score))}/10\\.0")

        if cve.attack_vector:
            lines.append(f"*Attack Vector:* {escape(cve.attack_vector)}")

        lines.append("")

        # Description
        description = cve.enriched_summary or cve.description
        if description:
            # Limit description length for Telegram (max message length is 4096 chars)
            max_desc_length = 800
            if len(description) > max_desc_length:
                description = description[:max_desc_length] + "..."
            lines.append(f"*Description:*")
            lines.append(escape(description))
            lines.append("")

        # Risk assessment (if available from LLM enrichment)
        if cve.risk_assessment:
            lines.append(f"*Risk Assessment:*")
            risk_text = cve.risk_assessment[:500]
            if len(cve.risk_assessment) > 500:
                risk_text += "..."
            lines.append(escape(risk_text))
            lines.append("")

        # Recommended actions (if available)
        if cve.recommended_actions:
            lines.append(f"*Recommended Actions:*")
            actions_text = cve.recommended_actions[:500]
            if len(cve.recommended_actions) > 500:
                actions_text += "..."
            lines.append(escape(actions_text))
            lines.append("")

        # Affected vendors/products
        if cve.affected_vendors:
            vendors = ", ".join(cve.affected_vendors[:5])
            if len(cve.affected_vendors) > 5:
                vendors += f" and {len(cve.affected_vendors) - 5} more"
            lines.append(f"*Vendors:* {escape(vendors)}")

        if cve.affected_products:
            products = ", ".join(cve.affected_products[:5])
            if len(cve.affected_products) > 5:
                products += f" and {len(cve.affected_products) - 5} more"
            lines.append(f"*Products:* {escape(products)}")

        lines.append("")

        # Published date
        pub_date = cve.published_date.strftime("%Y-%m-%d %H:%M UTC")
        lines.append(f"*Published:* {escape(pub_date)}")

        # NVD link (no need to escape URL)
        nvd_url = cve.nvd_url
        lines.append(f"*Details:* [NVD Link]({nvd_url})")

        # Join all lines
        message = "\n".join(lines)

        # Ensure message doesn't exceed Telegram's limit
        if len(message) > 4000:
            message = message[:3997] + "..."

        return message

    def get_notifier_name(self) -> str:
        return "TelegramNotifier"
