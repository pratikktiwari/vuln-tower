# Vuln Tower

**Vulnerability Tower** - CVE monitoring and notification system that fetches vulnerabilities from the National Vulnerability Database (NVD), applies configurable filters, optionally enriches data through middleware pipelines, and sends alerts to multiple notification channels.

## Overview

Vuln Tower is designed as a cron-based execution system suitable for deployment across various environments including VMs, Docker containers, Kubernetes CronJobs, GitHub Actions, and GitLab CI. It follows clean architecture principles with complete separation of concerns and zero hardcoded dependencies.

### Key Features

- **Multi-source CVE Fetching**: Primary support for NVD API with extensible architecture
- **Flexible Filtering**: CVSS score, keywords, products, vendors, attack vectors
- **Optional Enrichment Pipeline**: LLM-based analysis for risk assessment and recommendations
- **Multiple Notification Channels**: Discord, Slack, Microsoft Teams, Telegram via webhooks/APIs
- **Database Flexibility**: SQLite (default), PostgreSQL, MySQL support
- **Secret Management**: Environment variables (default) or custom Secret Store
- **Configuration-driven**: Single centralized configuration with sensible defaults

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Main Entrypoint                          │
│                  (Orchestration, No Business Logic)              │
└─────────────────────────────────────────────────────────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                ▼                 ▼                 ▼
         ┌──────────┐      ┌──────────┐     ┌──────────┐
         │  Config  │      │  Logger  │     │ Storage  │
         │ (Centralized)   │ (Structured)   │ (Factory) │
         └──────────┘      └──────────┘     └──────────┘
                │
                ▼
         ┌──────────┐
         │ Secrets  │
         │ Provider │
         └──────────┘
                │
       ┌────────┴────────┐
       ▼                 ▼
  ┌────────┐      ┌────────────┐
  │  Env   │      │   Custom   │
  └────────┘      └────────────┘

Execution Flow:
  1. Fetch CVEs (NVD) → 2. Deduplicate (Storage) → 3. Filter →
  4. Enrich (Pipeline) → 5. Notify (Channels) → 6. Persist State
```

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip
- (Optional) NVD API key for higher rate limits

### Installation

```bash
# Clone repository
git clone <repository-url>
cd vuln-tower

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export ENABLE_DISCORD=true
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
export MIN_CVSS_SCORE=7.0

# Run
python -m vuln_tower.main
```

### Docker

```bash
# Build image
docker build -t vuln-tower .

# Run with environment variables
docker run --rm \
  -e ENABLE_DISCORD=true \
  -e DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..." \
  -e MIN_CVSS_SCORE=7.0 \
  vuln-tower
```

## Configuration

All configuration is managed through environment variables. The system reads from a pluggable secret provider (environment variables by default, custom Secret Store optional).

### General Configuration

| Variable    | Default      | Description                                           |
| ----------- | ------------ | ----------------------------------------------------- |
| `APP_NAME`  | `vuln-tower` | Application name for logging                          |
| `LOG_LEVEL` | `INFO`       | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `RUN_MODE`  | `cron`       | Execution mode (cron, ci, local)                      |

### Database Configuration

| Variable      | Default         | Description                                       |
| ------------- | --------------- | ------------------------------------------------- |
| `DB_TYPE`     | `sqlite`        | Database type (sqlite, postgres, mysql)           |
| `DB_NAME`     | `vuln_tower.db` | Database name or file path                        |
| `DB_HOST`     | -               | Database host (required for postgres/mysql)       |
| `DB_PORT`     | -               | Database port (5432 for postgres, 3306 for mysql) |
| `DB_USER`     | -               | Database user (required for postgres/mysql)       |
| `DB_PASSWORD` | -               | Database password (required for postgres/mysql)   |

### NVD Configuration

| Variable               | Default | Description                                   |
| ---------------------- | ------- | --------------------------------------------- |
| `NVD_API_KEY`          | -       | NVD API key (optional, increases rate limits) |
| `FETCH_WINDOW_MINUTES` | `60`    | Time window for fetching recent CVEs          |
| `MAX_RESULTS_PER_RUN`  | `100`   | Maximum CVEs to process per execution         |
| `REQUEST_TIMEOUT`      | `30`    | HTTP request timeout in seconds               |

### Filter Configuration

| Variable         | Default | Description                                                 |
| ---------------- | ------- | ----------------------------------------------------------- |
| `MIN_CVSS_SCORE` | `0.0`   | Minimum CVSS score (0.0-10.0, 0 = allow all)                |
| `KEYWORDS`       | -       | Comma-separated keywords to match in description            |
| `PRODUCTS`       | -       | Comma-separated product names to filter                     |
| `VENDORS`        | -       | Comma-separated vendor names to filter                      |
| `ATTACK_VECTOR`  | -       | Required attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL) |

### Notification Configuration

| Variable              | Default | Description                          |
| --------------------- | ------- | ------------------------------------ |
| `ENABLE_DISCORD`      | `false` | Enable Discord notifications         |
| `DISCORD_WEBHOOK_URL` | -       | Discord webhook URL                  |
| `ENABLE_SLACK`        | `false` | Enable Slack notifications           |
| `SLACK_WEBHOOK_URL`   | -       | Slack webhook URL                    |
| `ENABLE_TEAMS`        | `false` | Enable Microsoft Teams notifications |
| `TEAMS_WEBHOOK_URL`   | -       | Teams webhook URL                    |
| `ENABLE_TELEGRAM`     | `false` | Enable Telegram notifications        |
| `TELEGRAM_BOT_TOKEN`  | -       | Telegram Bot API token               |
| `TELEGRAM_CHAT_ID`    | -       | Telegram chat ID                     |

### Pipeline Configuration

| Variable          | Default | Description                                  |
| ----------------- | ------- | -------------------------------------------- |
| `ENABLE_PIPELINE` | `false` | Enable enrichment pipeline                   |
| `PIPELINE_STEPS`  | -       | Comma-separated pipeline steps (e.g., "llm") |
| `LLM_PROVIDER`    | -       | LLM provider (openai)                        |
| `LLM_API_KEY`     | -       | LLM API key                                  |
| `LLM_MODEL`       | -       | LLM model identifier (e.g., gpt-4o-mini)     |

### Secret Provider Configuration

| Variable          | Default | Description                     |
| ----------------- | ------- | ------------------------------- |
| `SECRET_PROVIDER` | `env`   | Secret provider (env or custom) |

## Deployment Examples

### Kubernetes CronJob

```bash
# Apply configuration
kubectl apply -f kubernetes/cronjob.yaml

# Edit secrets
kubectl edit secret cve-notifier-secrets

# View logs
kubectl logs -l app=cve-notifier
```

See [kubernetes/cronjob.yaml](kubernetes/cronjob.yaml) for complete configuration.

### GitHub Actions

1. Configure secrets in repository settings:

   - `NVD_API_KEY`
   - `DISCORD_WEBHOOK_URL` (or Slack/Teams)
   - Optional: `LLM_API_KEY`

2. Workflow runs automatically on schedule
3. View execution in Actions tab

See [.github/workflows/cve-notifier.yml](.github/workflows/cve-notifier.yml) for details.

### GitLab CI

1. Configure CI/CD variables in project settings:

   - Protected variables for sensitive data
   - Regular variables for configuration

2. Set up pipeline schedule:
   - Go to CI/CD → Schedules
   - Create schedule with desired frequency

See [.gitlab-ci.yml](.gitlab-ci.yml) for configuration.

### VM Cron

```bash
# Run setup script
chmod +x deploy/vm-cron-setup.sh
./deploy/vm-cron-setup.sh

# Edit configuration
nano /opt/cve-notifier/.env

# Test execution
/opt/cve-notifier/run.sh

# Install crontab entry
(crontab -l; echo '0 * * * * /opt/cve-notifier/run.sh') | crontab -

# View logs
tail -f /var/log/cve-notifier/cve-notifier.log
```

## Secret Management

### Environment Variables (Default)

```bash
export NVD_API_KEY="your-key"
export DISCORD_WEBHOOK_URL="https://..."
```

## Development

### Project Structure

```
vuln_tower/
├── core/              # Configuration, logging, secrets
├── fetcher/           # CVE data sources (NVD)
├── filters/           # CVE filtering logic
├── pipeline/          # Enrichment middleware
├── notifier/          # Notification channels
├── storage/           # Database backends
├── formatter/         # Output formatting
├── models/            # Domain models
└── main.py            # Entrypoint orchestrator
```

### Adding a New Filter

```python
from vuln_tower.filters.base import CVEFilter
from vuln_tower.models import CVE

class CustomFilter(CVEFilter):
    def should_notify(self, cve: CVE) -> bool:
        # Your filter logic
        return True

    def get_filter_name(self) -> str:
        return "CustomFilter"
```

### Adding a New Notifier

```python
from vuln_tower.notifier.base import Notifier
from vuln_tower.models import CVE
from typing import List

class CustomNotifier(Notifier):
    def send(self, cves: List[CVE]):
        # Your notification logic
        pass

    def get_notifier_name(self) -> str:
        return "CustomNotifier"
```

### Adding Pipeline Steps

```python
from vuln_tower.pipeline.base import PipelineStep
from vuln_tower.models import CVE

class CustomEnricher(PipelineStep):
    def process(self, cve: CVE) -> CVE:
        # Your enrichment logic
        return cve

    def get_step_name(self) -> str:
        return "CustomEnricher"
```

## Testing

```bash
# Run with test configuration
export LOG_LEVEL=DEBUG
export RUN_MODE=local
export FETCH_WINDOW_MINUTES=1440  # Last 24 hours
export MIN_CVSS_SCORE=0.0  # Allow all for testing

python -m vuln_tower.main
```

## Troubleshooting

### No CVEs Found

- Check `FETCH_WINDOW_MINUTES` - may need to increase timeframe
- Verify NVD API is accessible
- Check filters are not too restrictive

### Database Errors

- Ensure database file directory is writable (SQLite)
- Verify connection credentials (PostgreSQL/MySQL)
- Check network connectivity to database host

### Notification Failures

- Verify webhook URLs are correct
- Check webhook service status
- Review rate limits for notification services
- Examine logs for detailed error messages

### Rate Limiting

- NVD API has rate limits (5 requests per 30 seconds without key)
- Obtain NVD API key for higher limits (50 requests per 30 seconds)
- Adjust `FETCH_WINDOW_MINUTES` to reduce frequency

## Security Considerations

1. **Webhook URLs**: Treat as sensitive credentials
2. **Database Credentials**: Use strong passwords, limit access
3. **API Keys**: Rotate regularly, use read-only keys where possible
4. **Secret Storage**: Use dedicated secret management (ENV, Vault, etc.)
5. **Network Access**: Restrict outbound connections to required services
6. **Container Security**: Run as non-root user (already configured)

## Performance

### Resource Usage

- Memory: ~50-100MB typical, up to 512MB with LLM enrichment
- CPU: Minimal during execution, spikes during API calls
- Storage: SQLite database grows at ~1KB per CVE
- Network: Depends on CVE volume and notification channels

### Optimization

- Use NVD API key to increase rate limits
- Adjust `FETCH_WINDOW_MINUTES` based on CVE volume
- Filter aggressively to reduce processing
- Disable pipeline enrichment if not needed
- Use PostgreSQL/MySQL for distributed deployments

## License

This project is provided as-is for educational and production use.

## Contributing

Contributions are welcome. Please ensure:

- Clean, readable code following existing patterns
- Type hints on all functions
- Docstrings for public APIs
- No hardcoded values
- Backward compatibility with configuration

## Support

For issues, questions, or feature requests, please file an issue in the repository.
