"""
Notification channel implementations.

Provides notifiers for Discord, Slack, Microsoft Teams, Telegram, and more.
"""

from typing import List

from vuln_tower.core import Config, StructuredLogger
from .base import Notifier
from .discord import DiscordNotifier
from .slack import SlackNotifier
from .teams import TeamsNotifier
from .telegram import TelegramNotifier


def create_notifiers(config: Config, logger: StructuredLogger) -> List[Notifier]:
    """
    Factory function to create enabled notifiers from configuration.

    Args:
        config: Application configuration
        logger: Structured logger instance

    Returns:
        List of active Notifier instances
    """
    notifiers: List[Notifier] = []
    notification_config = config.notification

    # Create Discord notifier if enabled
    if notification_config.enable_discord:
        if not notification_config.discord_webhook_url:
            logger.warning("Discord enabled but webhook URL not configured")
        else:
            notifiers.append(
                DiscordNotifier(notification_config.discord_webhook_url, logger)
            )

    # Create Slack notifier if enabled
    if notification_config.enable_slack:
        if not notification_config.slack_webhook_url:
            logger.warning("Slack enabled but webhook URL not configured")
        else:
            notifiers.append(
                SlackNotifier(notification_config.slack_webhook_url, logger)
            )

    # Create Teams notifier if enabled
    if notification_config.enable_teams:
        if not notification_config.teams_webhook_url:
            logger.warning("Teams enabled but webhook URL not configured")
        else:
            notifiers.append(
                TeamsNotifier(notification_config.teams_webhook_url, logger)
            )

    # Create Telegram notifier if enabled
    if notification_config.enable_telegram:
        if (
            not notification_config.telegram_bot_token
            or not notification_config.telegram_chat_id
        ):
            logger.warning("Telegram enabled but bot token or chat ID not configured")
        else:
            notifiers.append(
                TelegramNotifier(
                    notification_config.telegram_bot_token,
                    notification_config.telegram_chat_id,
                    logger,
                )
            )

    if not notifiers:
        logger.warning("No notification channels configured")
    else:
        logger.info(
            "Notifiers initialized",
            notifiers=[n.get_notifier_name() for n in notifiers],
        )

    return notifiers


__all__ = [
    "Notifier",
    "DiscordNotifier",
    "SlackNotifier",
    "TeamsNotifier",
    "TelegramNotifier",
    "create_notifiers",
]
