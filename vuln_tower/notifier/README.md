# Notifier Module

The `notifier` module implements notification delivery to various communication platforms via webhooks.

## Responsibilities

- Format CVE alerts for different platforms
- Send notifications via HTTP webhooks
- Handle platform-specific formatting requirements
- Graceful failure handling per channel

## Architecture

All notifiers implement the `Notifier` abstract interface:

```python
class Notifier(ABC):
    @abstractmethod
    def send(self, cves: List[CVE]):
        """Send CVE notifications"""

    @abstractmethod
    def get_notifier_name(self) -> str:
        """Return notifier name for logging"""
```

## Supported Channels

### Discord

Sends rich embedded messages to Discord channels via webhooks.

**Configuration**:

```bash
export ENABLE_DISCORD=true
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

**Format**: Discord Embeds

- Color-coded by severity (red=critical, orange=high, yellow=medium, green=low)
- Structured fields for metadata
- Clickable link to NVD
- Includes enriched data if available

**Setup**:

1. Open Discord server settings
2. Navigate to Integrations → Webhooks
3. Create webhook, copy URL
4. Set channel and optional name/avatar

**Rate Limits**: 30 requests per minute per webhook

### Slack

Sends Block Kit formatted messages to Slack channels.

**Configuration**:

```bash
export ENABLE_SLACK=true
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

**Format**: Slack Block Kit

- Header with severity emoji
- Formatted text blocks
- Metadata fact sets
- Action button linking to NVD

**Setup**:

1. Create Slack App: https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Add webhook to workspace
4. Copy webhook URL

**Rate Limits**: 1 request per second per webhook

### Microsoft Teams

Sends Adaptive Cards to Teams channels.

**Configuration**:

```bash
export ENABLE_TEAMS=true
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."
```

**Format**: Adaptive Cards

- Severity-based styling
- Fact sets for metadata
- Action button linking to NVD
- Compatible with Teams mobile

**Setup**:

1. Open Teams channel
2. Click … → Connectors
3. Configure Incoming Webhook
4. Name webhook, copy URL

**Rate Limits**: 4 requests per second per webhook

### Telegram

Sends formatted messages via Telegram Bot API.

**Configuration**:

```bash
export ENABLE_TELEGRAM=true
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
export TELEGRAM_CHAT_ID="-1001234567890"
```

**Format**: MarkdownV2

- Severity emojis (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- Formatted text with bold headers
- Inline links to NVD
- Support for enriched content (risk assessment, recommended actions)
- Automatic message length handling (max 4096 chars)

**Setup**:

1. Create a bot: Talk to @BotFather on Telegram
2. Send `/newbot` and follow instructions to get your bot token
3. Get chat ID:
   - For personal chat: Send a message to your bot, then visit `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - For groups: Add bot to group, make it admin (if needed), send a message, check getUpdates
   - For channels: Use channel username (e.g., `@yourchannel`) or numeric ID
4. Set bot token and chat ID in environment variables

**Rate Limits**: 30 messages per second per bot (across all chats)

**Special Features**:

- Web page preview enabled for NVD links
- Automatic text escaping for MarkdownV2
- Truncation for long descriptions while preserving formatting
- Support for both user chats, groups, and channels

## Message Formatting

Each notifier formats CVE data according to platform conventions:

### Common Elements

All platforms display:

- CVE ID as title/header
- Description or enriched summary
- CVSS score (if available)
- Severity level
- Attack vector
- Affected products
- Publication date
- Link to NVD details

### Enriched Content

If pipeline enrichment is enabled, messages include:

- Enriched summary (instead of raw description)
- Risk assessment section
- Recommended actions section

### Length Limits

Notifiers respect platform-specific length limits:

- Discord embeds: 2000 chars description, 1024 chars per field
- Slack blocks: 3000 chars per text block
- Teams cards: 1500 chars recommended for compatibility

Content is truncated with "..." if limits are exceeded.

## Usage Example

```python
from vuln_tower.core import Config, create_logger
from vuln_tower.notifier import create_notifiers

config = Config.load()
logger = create_logger("notifier_test", "INFO")

# Create notifiers from configuration
notifiers = create_notifiers(config, logger)

# Send notifications
for notifier in notifiers:
    try:
        notifier.send(cves)
        logger.info(f"Sent via {notifier.get_notifier_name()}")
    except Exception as e:
        logger.error(f"Failed: {e}")
```

## Error Handling

Notifiers implement per-CVE error handling:

```python
for cve in cves:
    try:
        self._send_single(cve)
    except Exception as e:
        logger.error("Failed to send", cve_id=cve.cve_id, error=str(e))
        # Continue with next CVE
```

Failures for individual CVEs don't prevent other notifications.

## Multiple Channels

Enable multiple channels simultaneously:

```bash
export ENABLE_DISCORD=true
export DISCORD_WEBHOOK_URL="https://..."

export ENABLE_SLACK=true
export SLACK_WEBHOOK_URL="https://..."

export ENABLE_TEAMS=true
export TEAMS_WEBHOOK_URL="https://..."
```

Each CVE is sent to all enabled channels independently.

## Custom Notifiers

### Creating a Custom Notifier

```python
from vuln_tower.notifier.base import Notifier
from vuln_tower.models import CVE
from typing import List
import requests

class EmailNotifier(Notifier):
    """Send CVE notifications via email"""

    def __init__(self, smtp_host: str, recipient: str, logger):
        self.smtp_host = smtp_host
        self.recipient = recipient
        self.logger = logger

    def send(self, cves: List[CVE]):
        for cve in cves:
            try:
                self._send_email(cve)
            except Exception as e:
                self.logger.error(
                    "Email failed",
                    cve_id=cve.cve_id,
                    error=str(e)
                )

    def _send_email(self, cve: CVE):
        subject = f"[CVE Alert] {cve.cve_id} - {cve.severity}"
        body = self._format_email_body(cve)
        # Send via SMTP...

    def get_notifier_name(self) -> str:
        return "EmailNotifier"
```

### Registering Custom Notifier

Update `notifier/__init__.py`:

```python
def create_notifiers(config: Config, logger: StructuredLogger) -> List[Notifier]:
    notifiers = []

    # Existing notifiers...

    # Add custom notifier
    if config.notification.enable_email:
        notifiers.append(EmailNotifier(
            smtp_host=config.notification.smtp_host,
            recipient=config.notification.email_recipient,
            logger=logger
        ))

    return notifiers
```

## Webhook Security

### Best Practices

1. **Treat URLs as secrets**: Never commit webhook URLs to version control
2. **Use environment variables**: Store in secure secret management
3. **Rotate regularly**: Regenerate webhooks periodically
4. **Restrict permissions**: Grant minimal required permissions
5. **Monitor usage**: Watch for unexpected webhook calls

### Webhook URL Format

Each platform has distinct URL patterns:

- Discord: `https://discord.com/api/webhooks/{id}/{token}`
- Slack: `https://hooks.slack.com/services/{T}/{B}/{token}`
- Teams: `https://{tenant}.webhook.office.com/webhookb2/{id}/{token}`

Never share or log these URLs.

## Testing Notifiers

### Local Testing

```python
from vuln_tower.notifier.discord import DiscordNotifier
from vuln_tower.core import create_logger
from vuln_tower.models import CVE
from datetime import datetime

logger = create_logger("test", "INFO")
notifier = DiscordNotifier(
    webhook_url="https://discord.com/api/webhooks/...",
    logger=logger
)

test_cve = CVE(
    cve_id="CVE-2024-TEST",
    description="Test notification",
    published_date=datetime.utcnow(),
    last_modified_date=datetime.utcnow(),
    cvss_score=8.5,
    severity="HIGH",
    affected_vendors=["test"],
    affected_products=["test-product"],
    references=[],
    cwe_ids=[],
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    attack_vector="NETWORK",
    attack_complexity="LOW"
)

notifier.send([test_cve])
```

### Webhook Validation

Test webhooks without running full system:

```bash
# Discord
curl -X POST "https://discord.com/api/webhooks/..." \
  -H "Content-Type: application/json" \
  -d '{"content":"Test message"}'

# Slack
curl -X POST "https://hooks.slack.com/services/..." \
  -H "Content-Type: application/json" \
  -d '{"text":"Test message"}'

# Teams
curl -X POST "https://outlook.office.com/webhook/..." \
  -H "Content-Type: application/json" \
  -d '{"text":"Test message"}'
```

## Troubleshooting

### Notifications Not Received

**Check**:

1. Webhook URL is correct
2. Webhook is not disabled/deleted
3. Channel permissions allow webhook posts
4. Rate limits not exceeded
5. Network connectivity to webhook endpoint

**Debug**:

```bash
export LOG_LEVEL=DEBUG
python -m vuln_tower.main
# Check logs for HTTP errors
```

### Rate Limiting

**Symptoms**:

- HTTP 429 errors in logs
- Some notifications missing

**Solutions**:

- Reduce notification frequency
- Batch multiple CVEs per message (requires code changes)
- Distribute across multiple webhooks
- Add delays between sends

### Formatting Issues

**Symptoms**:

- Messages appear broken
- Missing fields
- Truncated content

**Solutions**:

- Check platform-specific character limits
- Verify JSON structure
- Test with simple CVEs first
- Review platform documentation

## Platform-Specific Notes

### Discord

- Supports up to 10 embeds per message
- Embed limits: 256 char title, 2048 char description
- Maximum 25 fields per embed
- Color is an integer (hex without #)

### Slack

- Block Kit has strict validation
- Maximum 50 blocks per message
- Text sections limited to 3000 chars
- Fallback text recommended for notifications

### Teams

- Adaptive Card schema version matters
- Some features require specific Teams versions
- Mobile rendering differs from desktop
- Action buttons may require specific permissions

## Performance

### Concurrent Sending

Currently, notifiers send sequentially. For high-volume scenarios, consider:

```python
import concurrent.futures

def notify_concurrent(notifiers, cves):
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(notifier.send, cves)
            for notifier in notifiers
        ]
        concurrent.futures.wait(futures)
```

### Batching

For large CVE volumes, batch messages:

```python
def send(self, cves: List[CVE]):
    batch_size = 5
    for i in range(0, len(cves), batch_size):
        batch = cves[i:i+batch_size]
        self._send_batch(batch)
```

## Comparison Matrix

| Feature          | Discord   | Slack     | Teams   |
| ---------------- | --------- | --------- | ------- |
| Rich formatting  | Excellent | Excellent | Good    |
| Mobile support   | Excellent | Excellent | Good    |
| Setup complexity | Easy      | Medium    | Medium  |
| Rate limits      | 30/min    | 1/sec     | 4/sec   |
| Free tier        | Yes       | Yes       | Yes     |
| Authentication   | Webhook   | Webhook   | Webhook |
| Link previews    | Yes       | Yes       | Limited |
