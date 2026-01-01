# Fetcher Module

The `fetcher` module retrieves CVE data from external vulnerability databases.

## Responsibilities

- Fetch CVEs from external APIs
- Parse and normalize data to internal CVE model
- Handle API authentication and rate limiting
- Manage time windows for incremental fetching

## Architecture

All fetchers implement the `CVEFetcher` abstract interface:

```python
class CVEFetcher(ABC):
    @abstractmethod
    def fetch(self) -> List[CVE]:
        """Fetch CVEs from data source"""
```

## NVD Fetcher

Primary implementation that fetches from the National Vulnerability Database (NVD) API v2.0.

### Configuration

```bash
# Optional API key (strongly recommended)
export NVD_API_KEY="your-api-key"

# Fetch window (default: 60 minutes)
export FETCH_WINDOW_MINUTES=60

# Maximum results per execution
export MAX_RESULTS_PER_RUN=100

# Request timeout
export REQUEST_TIMEOUT=30
```

### API Key Benefits

**Without API key**:

- 5 requests per 30 seconds
- Suitable for testing only

**With API key**:

- 50 requests per 30 seconds
- More reliable service

**Get API key**: https://nvd.nist.gov/developers/request-an-api-key

### Fetch Window

The fetch window determines which CVEs are retrieved based on publication date:

```
Current Time: 2024-01-15 14:00:00
Fetch Window: 60 minutes
Query Range: 2024-01-15 13:00:00 to 2024-01-15 14:00:00
```

**Considerations**:

- Smaller windows reduce API load but may miss CVEs
- Larger windows ensure complete coverage but increase processing
- Recommended: 60-120 minutes for hourly cron jobs
- For daily runs: 1440 minutes (24 hours)

### Data Mapping

NVD API response fields are mapped to the CVE domain model:

| NVD Field                                            | CVE Model Field                         | Notes               |
| ---------------------------------------------------- | --------------------------------------- | ------------------- |
| `cve.id`                                             | `cve_id`                                | CVE identifier      |
| `cve.descriptions[lang=en].value`                    | `description`                           | English description |
| `cve.published`                                      | `published_date`                        | ISO timestamp       |
| `cve.lastModified`                                   | `last_modified_date`                    | ISO timestamp       |
| `metrics.cvssMetricV31[0].cvssData.baseScore`        | `cvss_score`                            | CVSS v3.1 score     |
| `metrics.cvssMetricV31[0].cvssData.vectorString`     | `cvss_vector`                           | CVSS vector         |
| `metrics.cvssMetricV31[0].baseSeverity`              | `severity`                              | Severity rating     |
| `configurations.nodes.cpeMatch.criteria`             | `affected_vendors`, `affected_products` | Parsed from CPE     |
| `cve.references`                                     | `references`                            | URLs                |
| `cve.weaknesses.description`                         | `cwe_ids`                               | CWE identifiers     |
| `metrics.cvssMetricV31[0].cvssData.attackVector`     | `attack_vector`                         | Attack vector       |
| `metrics.cvssMetricV31[0].cvssData.attackComplexity` | `attack_complexity`                     | Attack complexity   |

### CVSS Version Fallback

The fetcher attempts multiple CVSS versions in order:

1. CVSS v3.1 (preferred)
2. CVSS v3.0
3. CVSS v2.0

First available version is used.

### CPE Parsing

Affected products and vendors are extracted from CPE (Common Platform Enumeration) strings:

```
CPE: cpe:2.3:a:vendor:product:version:...
                    ↓      ↓
    affected_vendors: ["vendor"]
    affected_products: ["product"]
```

Wildcards (\*) are filtered out.

## Usage Example

```python
from vuln_tower.core import Config, create_logger
from vuln_tower.fetcher import NVDFetcher

config = Config.load()
logger = create_logger("fetcher", "INFO")

fetcher = NVDFetcher(config, logger)
cves = fetcher.fetch()

for cve in cves:
    print(f"{cve.cve_id}: {cve.severity} - {cve.cvss_score}")
```

## Error Handling

The fetcher handles various failure scenarios:

### Network Errors

```python
try:
    response = requests.get(...)
except requests.RequestException as e:
    logger.error("Failed to fetch from NVD", error=str(e))
    raise RuntimeError(f"NVD API request failed: {e}")
```

Failed fetches raise `RuntimeError`, preventing partial processing.

### Parsing Errors

Individual CVE parsing errors are logged but don't stop processing:

```python
for item in vulnerabilities:
    try:
        cve = self._parse_cve(item)
        if cve:
            cves.append(cve)
    except Exception as e:
        logger.error("Failed to parse CVE", error=str(e))
        # Continue with next CVE
```

### Incomplete Data

CVEs with missing critical fields (e.g., CVE ID) are skipped:

```python
if not cve_id:
    return None  # Skip this CVE
```

## Rate Limiting

The fetcher does not implement client-side rate limiting. Instead:

1. Relies on NVD's server-side rate limiting
2. Uses appropriate `FETCH_WINDOW_MINUTES` to limit data volume
3. Respects `MAX_RESULTS_PER_RUN` to cap processing

For high-frequency execution, consider:

- Implementing exponential backoff
- Adding request delays
- Monitoring 429 (Too Many Requests) responses

## Testing

### Local Testing

```python
from vuln_tower.core import Config
from vuln_tower.fetcher import NVDFetcher

# Override config for testing
config = Config.load()
config.nvd.fetch_window_minutes = 1440  # Last 24 hours
config.nvd.max_results_per_run = 10  # Small sample

fetcher = NVDFetcher(config, logger)
cves = fetcher.fetch()

print(f"Fetched {len(cves)} CVEs")
```

### Mocking

For unit tests, mock the NVD API:

```python
import unittest
from unittest.mock import patch, MagicMock

class TestNVDFetcher(unittest.TestCase):
    @patch('requests.get')
    def test_fetch(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [...]
        }
        mock_get.return_value = mock_response

        fetcher = NVDFetcher(config, logger)
        cves = fetcher.fetch()

        self.assertGreater(len(cves), 0)
```

## Custom Fetchers

### Creating a Custom Fetcher

```python
from vuln_tower.fetcher.base import CVEFetcher
from vuln_tower.models import CVE
from typing import List

class GitHubAdvisoryFetcher(CVEFetcher):
    """Fetch CVEs from GitHub Security Advisories"""

    def __init__(self, token: str, logger):
        self.token = token
        self.logger = logger

    def fetch(self) -> List[CVE]:
        # GraphQL query to GitHub API
        advisories = self._query_github_api()

        cves = []
        for advisory in advisories:
            cve = self._parse_advisory(advisory)
            if cve:
                cves.append(cve)

        return cves

    def _parse_advisory(self, advisory: dict) -> CVE:
        # Map GitHub advisory to CVE model
        return CVE(...)
```

### Integrating Custom Fetcher

Update `main.py`:

```python
# Instead of hardcoded NVDFetcher
fetcher_type = config.general.fetcher_type
if fetcher_type == "nvd":
    fetcher = NVDFetcher(config, logger)
elif fetcher_type == "github":
    fetcher = GitHubAdvisoryFetcher(config, logger)
```

## API Documentation

**NVD API v2.0**: https://nvd.nist.gov/developers/vulnerabilities

**Key Endpoints**:

- `/rest/json/cves/2.0`: Query CVEs
- Parameters:
  - `pubStartDate`: Start of publication date range
  - `pubEndDate`: End of publication date range
  - `resultsPerPage`: Results per page (max 2000)
  - `startIndex`: Pagination offset

**Response Format**:

```json
{
  "resultsPerPage": 100,
  "startIndex": 0,
  "totalResults": 250,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-1234",
        "descriptions": [...],
        "metrics": {...},
        "configurations": [...],
        "references": [...]
      }
    }
  ]
}
```

## Performance

### Typical Response Times

- With API key: 1-3 seconds per request
- Without API key: 2-5 seconds per request
- Network latency: +500ms to 2s

### Optimization

1. **Use API key**: Faster, more reliable
2. **Appropriate fetch window**: Balance completeness vs. performance
3. **Limit results**: Use `MAX_RESULTS_PER_RUN` cap
4. **Request timeout**: Set reasonable `REQUEST_TIMEOUT`

### Pagination

Current implementation fetches single page. For large windows:

```python
def fetch_paginated(self) -> List[CVE]:
    all_cves = []
    start_index = 0
    results_per_page = 100

    while True:
        params = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
            ...
        }

        response = requests.get(self.API_BASE, params=params)
        data = response.json()

        cves = self._parse_vulnerabilities(data["vulnerabilities"])
        all_cves.extend(cves)

        if len(cves) < results_per_page:
            break

        start_index += results_per_page

    return all_cves
```

## Troubleshooting

### No CVEs Returned

**Possible causes**:

- Fetch window too small
- No new CVEs published recently
- API connectivity issues
- Rate limiting

**Debug**:

```bash
export LOG_LEVEL=DEBUG
export FETCH_WINDOW_MINUTES=1440  # Last 24 hours
python -m vuln_tower.main
```

### HTTP 403 Forbidden

**Cause**: Invalid or expired API key

**Solution**: Verify `NVD_API_KEY` or remove to use public access

### HTTP 429 Too Many Requests

**Cause**: Rate limit exceeded

**Solution**:

- Add API key for higher limits
- Reduce execution frequency
- Increase time between requests

### Parsing Errors

**Symptoms**: Logs show "Failed to parse CVE"

**Causes**:

- NVD API schema changes
- Malformed CVE data
- Missing required fields

**Debug**: Check specific CVE on NVD website
