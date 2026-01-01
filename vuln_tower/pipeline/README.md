# Pipeline Module

The `pipeline` module implements a middleware pattern for enriching and transforming CVE data before notification.

## Responsibilities

- CVE enrichment and augmentation
- Composable transformation steps
- Graceful failure handling
- Optional LLM-based analysis

## Architecture

```
Pipeline
  ├── PipelineStep (Abstract)
  │     └── LLMEnricher
  └── Additional steps...
```

Pipeline executes steps sequentially, passing the CVE through each step. Steps can:

- Add enriched data (summaries, risk assessments, recommendations)
- Transform existing data
- Annotate with metadata

## Configuration

```bash
# Enable pipeline
export ENABLE_PIPELINE=true

# Specify steps (comma-separated)
export PIPELINE_STEPS="llm"

# LLM configuration (if using LLM enricher)
export LLM_PROVIDER=openai
export LLM_API_KEY=sk-...
export LLM_MODEL=gpt-4o-mini
```

## Pipeline Steps

### LLMEnricher

Uses large language models to generate contextual insights about CVEs.

**Capabilities**:

- Concise summaries in plain language
- Risk assessments based on vulnerability characteristics
- Recommended actions for security teams

**Supported Providers**:

- OpenAI (default)
- Any OpenAI API-compatible endpoint

**Configuration**:

```bash
export LLM_PROVIDER=openai
export LLM_API_KEY=sk-...
export LLM_MODEL=gpt-4o-mini  # or gpt-4, gpt-3.5-turbo, etc.
```

**Output Fields**:

- `enriched_summary`: 1-2 sentence technical summary
- `risk_assessment`: Brief impact and risk analysis
- `recommended_actions`: Specific mitigation steps

**Example Output**:

```
enriched_summary: "Critical authentication bypass in nginx versions 1.20.0-1.21.5
                   allows unauthenticated remote attackers to gain administrative access."

risk_assessment: "High risk for internet-facing nginx deployments. Exploitation
                  requires no authentication and can lead to full system compromise."

recommended_actions: "Immediately upgrade to nginx 1.21.6 or later. If immediate
                     patching is not possible, restrict administrative interface
                     access via firewall rules."
```

**Error Handling**:

- Failures are logged but don't stop processing
- Original CVE is returned if enrichment fails
- Network timeouts are caught gracefully
- API errors don't affect notification delivery

**Cost Considerations**:

- Each CVE = 1 API call
- Typical token usage: ~500 input + 200 output tokens
- Estimated cost with GPT-4o-mini: ~$0.001 per CVE
- Consider using `MAX_RESULTS_PER_RUN` to control costs

## Pipeline Execution

The pipeline processes each CVE sequentially through all configured steps:

```python
for cve in cves:
    enriched_cve = pipeline.process(cve)
    # enriched_cve now has additional fields populated
```

If a step fails:

1. Error is logged with CVE ID and step name
2. Original CVE is used
3. Next step continues processing
4. Notification proceeds normally

This ensures pipeline failures never prevent critical notifications.

## Usage Example

```python
from vuln_tower.core import Config, create_logger
from vuln_tower.pipeline import create_pipeline

config = Config.load()
logger = create_logger("pipeline_test", "INFO")

# Create pipeline from configuration
pipeline = create_pipeline(config, logger)

# Process a CVE
enriched_cve = pipeline.process(cve)

# Access enriched fields
if enriched_cve.enriched_summary:
    print(enriched_cve.enriched_summary)
if enriched_cve.risk_assessment:
    print(enriched_cve.risk_assessment)
```

## Custom Pipeline Steps

### Creating a Custom Step

```python
from vuln_tower.pipeline.base import PipelineStep
from vuln_tower.models import CVE

class CPEExtractor(PipelineStep):
    """Extract and format CPE information"""

    def process(self, cve: CVE) -> CVE:
        # Transform affected_products into formatted CPE strings
        cpe_list = [
            f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
            for vendor in cve.affected_vendors
            for product in cve.affected_products
        ]

        # Store in enriched_summary or custom field
        cve_dict = cve.__dict__.copy()
        cve_dict['enriched_summary'] = f"CPEs: {', '.join(cpe_list[:5])}"

        return CVE(**cve_dict)

    def get_step_name(self) -> str:
        return "CPEExtractor"
```

### Registering Custom Step

Update `pipeline/__init__.py`:

```python
def create_pipeline(config: Config, logger: StructuredLogger) -> Pipeline:
    steps = []

    for step_name in config.pipeline.pipeline_steps:
        if step_name == "llm":
            steps.append(LLMEnricher(config, logger))
        elif step_name == "cpe":
            steps.append(CPEExtractor())
        # Add more steps...

    return Pipeline(steps, logger)
```

## Pipeline Patterns

### Enrichment Only

Add contextual information without modifying core CVE data.

```python
class SeverityExplainer(PipelineStep):
    def process(self, cve: CVE) -> CVE:
        explanations = {
            "CRITICAL": "Requires immediate attention",
            "HIGH": "Prioritize patching within 24-48 hours",
            "MEDIUM": "Schedule patching within 1 week",
            "LOW": "Address during regular maintenance"
        }

        cve_dict = cve.__dict__.copy()
        cve_dict['recommended_actions'] = explanations.get(
            cve.severity,
            "Evaluate based on your environment"
        )
        return CVE(**cve_dict)
```

### Validation

Check data quality and add warnings.

```python
class CVSSValidator(PipelineStep):
    def process(self, cve: CVE) -> CVE:
        if cve.cvss_score is None:
            cve_dict = cve.__dict__.copy()
            cve_dict['risk_assessment'] = "WARNING: No CVSS score available"
            return CVE(**cve_dict)
        return cve
```

### External Data Integration

Fetch additional context from external sources.

```python
class ExploitDBChecker(PipelineStep):
    def process(self, cve: CVE) -> CVE:
        # Check if exploits exist in ExploitDB
        has_exploit = self._check_exploitdb(cve.cve_id)

        if has_exploit:
            cve_dict = cve.__dict__.copy()
            cve_dict['risk_assessment'] = "PUBLIC EXPLOIT AVAILABLE - HIGH PRIORITY"
            return CVE(**cve_dict)

        return cve
```

## Performance Considerations

### Serial Execution

Steps execute sequentially for each CVE:

- Predictable behavior
- Clear error attribution
- Simple debugging

For parallel processing, consider:

- Batch processing within steps
- Async operations
- Connection pooling

### Caching

LLM enricher includes no persistent caching (stateless execution model).

To add caching:

```python
class CachedLLMEnricher(LLMEnricher):
    def __init__(self, config, logger, cache_backend):
        super().__init__(config, logger)
        self.cache = cache_backend

    def process(self, cve: CVE) -> CVE:
        cached = self.cache.get(cve.cve_id)
        if cached:
            return cached

        enriched = super().process(cve)
        self.cache.set(cve.cve_id, enriched)
        return enriched
```

## Best Practices

1. **Keep steps focused**: Each step should have a single responsibility
2. **Handle failures gracefully**: Never let one CVE's failure affect others
3. **Log liberally**: Pipeline errors should be visible but not fatal
4. **Return valid CVEs**: Always return a valid CVE object, even on error
5. **Consider costs**: LLM calls add latency and expense
6. **Test independently**: Unit test each step in isolation
7. **Document outputs**: Clearly specify which fields each step modifies

## Disabling Pipeline

To run without enrichment:

```bash
export ENABLE_PIPELINE=false
```

Or omit pipeline configuration entirely. The system works perfectly without any pipeline steps - it's purely optional enrichment.

## Troubleshooting

### LLM Enrichment Failures

**Symptoms**:

- Logs show "LLM enrichment failed"
- CVEs lack enriched fields

**Solutions**:

- Verify `LLM_API_KEY` is correct
- Check API endpoint accessibility
- Review rate limits
- Ensure sufficient API credits

### High Latency

**Symptoms**:

- Slow execution times
- Timeout errors

**Solutions**:

- Reduce `MAX_RESULTS_PER_RUN`
- Use faster LLM models (gpt-4o-mini vs gpt-4)
- Disable pipeline for time-critical deployments
- Implement caching layer

### Memory Issues

**Symptoms**:

- Out of memory errors
- Pod restarts in Kubernetes

**Solutions**:

- Increase memory limits
- Process CVEs in smaller batches
- Disable resource-intensive steps
- Use streaming where possible
