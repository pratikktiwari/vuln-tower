# Core Module

The `core` module provides foundational infrastructure for the Vuln Tower system.

## Responsibilities

- Centralized configuration management
- Structured logging
- Secret provider abstraction
- Execution context tracking

## Components

### Configuration (`config.py`)

Single source of truth for all application configuration. This is the ONLY module that reads environment variables directly.

**Design Principle**: All other modules receive configuration via dependency injection, never reading environment variables themselves.

```python
from vuln_tower.core import Config

config = Config.load()
print(config.database.db_type)
print(config.nvd.fetch_window_minutes)
```

Configuration is immutable after loading, implemented using frozen dataclasses.

### Logger (`logger.py`)

Structured logging with consistent formatting across the application.

```python
from vuln_tower.core import create_logger

logger = create_logger("my_component", "INFO")
logger.info("Processing CVE", cve_id="CVE-2024-1234", severity="HIGH")
```

Output format:

```
2024-01-01 10:30:45 | INFO     | my_component | Processing CVE | cve_id=CVE-2024-1234 | severity=HIGH
```

### Scheduler Context (`scheduler_context.py`)

Tracks execution metadata for debugging and auditing.

```python
from vuln_tower.core import SchedulerContext

context = SchedulerContext.create("cron")
# ... do work ...
context.complete()

print(f"Duration: {context.duration_seconds}s")
```

Captures:

- Unique run ID
- Start/end timestamps
- Hostname
- Platform
- Execution mode

### Secret Providers (`secrets/`)

Pluggable abstraction for loading secrets from various backends.

**Base Interface** (`base.py`):

```python
class SecretProvider(ABC):
    @abstractmethod
    def get_secret(self, key: str) -> Optional[str]:
        pass

    @abstractmethod
    def get_required_secret(self, key: str) -> str:
        pass
```

**Implementations**:

1. **Environment Variables** (`env_provider.py`): Default provider, reads from `os.environ`

2. **Custom**: Implement your own secret provider like azure key vault, hashicorp, etc.

**Provider Selection**:

````bash
# Use environment variables (default)
export SECRET_PROVIDER=env

## Configuration Reference

All configuration is loaded through the centralized `Config.load()` method:

- `GeneralConfig`: Application-level settings
- `DatabaseConfig`: Database connection parameters
- `NVDConfig`: NVD API settings
- `FilterConfig`: CVE filtering criteria
- `NotificationConfig`: Notification channel toggles and URLs
- `PipelineConfig`: Middleware pipeline settings

## Extension Points

### Adding a New Secret Provider

1. Implement `SecretProvider` interface in `secrets/`
2. Update `_get_secret_provider()` factory in `config.py`
3. Document required bootstrap credentials

### Adding Configuration Sections

1. Create a frozen dataclass in `config.py`
2. Add static `load()` method using `_get_*` helper functions
3. Include in root `Config` dataclass
4. Document environment variables in README

## Best Practices

1. **Never read environment variables outside this module**
2. **Always use dependency injection** to pass config to components
3. **Validate configuration early** during initialization
4. **Provide sensible defaults** for all non-required settings
5. **Document all environment variables** with type and purpose
6. **Keep secrets out of logs** by using structured context carefully
7. **Use frozen dataclasses** to prevent accidental mutation

## Testing Configuration

For local testing, create a `.env` file:

```bash
# .env
export LOG_LEVEL=DEBUG
export DB_TYPE=sqlite
export DB_NAME=test.db
export MIN_CVSS_SCORE=0.0
````

Then source it:

```bash
source .env
python -m vuln_tower.main
```
