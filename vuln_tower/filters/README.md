# Filters Module

The `filters` module provides pluggable CVE filtering logic to determine which vulnerabilities should trigger notifications.

## Responsibilities

- Evaluate CVEs against configurable criteria
- Support multiple filter types
- Composable filter chains
- Fail-safe defaults (allow all when unconfigured)

## Architecture

All filters implement the `CVEFilter` abstract interface:

```python
class CVEFilter(ABC):
    @abstractmethod
    def should_notify(self, cve: CVE) -> bool:
        """Return True if CVE should be notified"""

    @abstractmethod
    def get_filter_name(self) -> str:
        """Return filter name for logging"""
```

## Available Filters

### CVSSFilter

Filters based on minimum CVSS base score.

**Configuration**:

```bash
export MIN_CVSS_SCORE=7.0  # Only HIGH and CRITICAL
```

**Behavior**:

- CVEs with score >= threshold pass
- CVEs without scores are excluded unless threshold is 0.0
- Score range: 0.0 - 10.0

**Use Cases**:

- Focus on severe vulnerabilities
- Reduce notification noise
- Prioritize patching efforts

### KeywordFilter

Filters based on keywords appearing in CVE description.

**Configuration**:

```bash
export KEYWORDS="kubernetes,docker,nginx,apache"
```

**Behavior**:

- Case-insensitive matching
- Empty list allows all CVEs
- At least one keyword must match
- Matches partial words

**Use Cases**:

- Technology-specific monitoring
- Filter by vulnerability type (e.g., "rce", "injection")
- Track specific threats

### ProductFilter

Filters based on affected products.

**Configuration**:

```bash
export PRODUCTS="linux_kernel,nginx,postgresql"
```

**Behavior**:

- Case-insensitive matching
- Checks against affected products from CPE data
- Empty list allows all CVEs

**Use Cases**:

- Monitor specific applications
- Track dependencies
- Infrastructure-specific alerts

### VendorFilter

Filters based on affected vendors.

**Configuration**:

```bash
export VENDORS="microsoft,google,apple,redhat"
```

**Behavior**:

- Case-insensitive matching
- Checks against vendor names from CPE data
- Empty list allows all CVEs

**Use Cases**:

- Track specific vendors
- Monitor ecosystem vulnerabilities
- Compliance requirements

### AttackVectorFilter

Filters based on CVSS attack vector.

**Configuration**:

```bash
export ATTACK_VECTOR=NETWORK
```

**Values**:

- `NETWORK`: Remotely exploitable
- `ADJACENT`: Adjacent network access
- `LOCAL`: Local access required
- `PHYSICAL`: Physical access required

**Behavior**:

- Case-insensitive matching
- CVEs without attack vector data are allowed
- Matches exact value

**Use Cases**:

- Prioritize remotely exploitable vulnerabilities
- Focus on realistic threats to your environment

## Filter Chain Behavior

Multiple filters are combined with AND logic:

```
CVE passes if:
  CVSS score >= threshold
  AND (keyword matches OR no keywords configured)
  AND (product matches OR no products configured)
  AND (vendor matches OR no vendors configured)
  AND (attack vector matches OR no vector configured)
```

A CVE must pass ALL active filters to generate a notification.

## Configuration Example

```bash
# Only critical remote vulnerabilities in specific products
export MIN_CVSS_SCORE=9.0
export ATTACK_VECTOR=NETWORK
export PRODUCTS="nginx,apache,tomcat"
export KEYWORDS="remote code execution,rce"
```

This configuration will only notify about:

- CVSS score >= 9.0
- Network-exploitable
- Affecting nginx, apache, or tomcat
- Containing "remote code execution" or "rce" in description

## Usage in Code

```python
from vuln_tower.core import Config
from vuln_tower.filters import create_filters

config = Config.load()
filters = create_filters(config)

for cve in cves:
    passes_all = all(f.should_notify(cve) for f in filters)
    if passes_all:
        # Notify
        pass
```

## Custom Filters

### Creating a Custom Filter

```python
from vuln_tower.filters.base import CVEFilter
from vuln_tower.models import CVE

class AgeFilter(CVEFilter):
    """Only notify about CVEs published within last N days"""

    def __init__(self, max_age_days: int):
        self.max_age_days = max_age_days

    def should_notify(self, cve: CVE) -> bool:
        age = datetime.utcnow() - cve.published_date
        return age.days <= self.max_age_days

    def get_filter_name(self) -> str:
        return f"AgeFilter(max_age_days={self.max_age_days})"
```

### Registering Custom Filter

Update `filters/__init__.py`:

```python
def create_filters(config: Config) -> List[CVEFilter]:
    filters = []

    # Existing filters...

    # Add custom filter
    max_age = _get_int("MAX_CVE_AGE_DAYS", 0)
    if max_age > 0:
        filters.append(AgeFilter(max_age))

    return filters
```

## Performance

Filters are executed sequentially with short-circuit evaluation:

- First failing filter stops evaluation
- Order filters by likelihood of failure for efficiency
- Current order: CVSS → Keywords → Products → Vendors → Attack Vector

## Testing Filters

Test filters in isolation:

```python
from vuln_tower.filters import CVSSFilter
from vuln_tower.models import CVE

filter = CVSSFilter(min_score=7.0)

cve_high = CVE(cvss_score=8.5, ...)
assert filter.should_notify(cve_high) == True

cve_low = CVE(cvss_score=3.2, ...)
assert filter.should_notify(cve_low) == False
```

## Best Practices

1. **Start permissive, then refine**: Begin with loose filters and tighten based on notification volume
2. **Monitor filter effectiveness**: Log filter decisions to understand what's being excluded
3. **Combine complementary filters**: CVSS + Attack Vector is more effective than either alone
4. **Test filter changes**: Verify filters don't exclude important CVEs
5. **Document filter rationale**: Explain why specific thresholds were chosen

## Common Patterns

### High-severity, remotely exploitable only

```bash
export MIN_CVSS_SCORE=7.0
export ATTACK_VECTOR=NETWORK
```

### Technology stack monitoring

```bash
export PRODUCTS="python,django,postgresql,redis"
export KEYWORDS="django,python"
```

### Vendor-specific tracking

```bash
export VENDORS="microsoft,adobe"
export MIN_CVSS_SCORE=5.0
```

### Zero-day focus

```bash
export KEYWORDS="zero-day,0day,in the wild,exploit"
export MIN_CVSS_SCORE=0.0  # Don't filter by score
```
