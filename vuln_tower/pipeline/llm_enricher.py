"""
LLM-based CVE enrichment step.

Uses language models to generate enriched summaries, risk assessments,
and recommended actions for CVEs.
"""

from typing import Optional
import json

try:
    import openai
except ImportError:
    openai = None

from vuln_tower.core import Config, StructuredLogger
from vuln_tower.models import CVE
from .base import PipelineStep


class LLMEnricher(PipelineStep):
    """
    Enriches CVEs using Large Language Models.

    Supports OpenAI API-compatible providers (OpenAI, Azure OpenAI, etc.)
    Generates:
    - Concise summaries
    - Risk assessments
    - Recommended actions
    """

    def __init__(self, config: Config, logger: StructuredLogger):
        """
        Initialize LLM enricher.

        Args:
            config: Application configuration
            logger: Structured logger instance
        """
        if openai is None:
            raise ImportError(
                "openai package is required for LLM enrichment. "
                "Install with: pip install openai"
            )

        self.config = config
        self.logger = logger

        pipeline_config = config.pipeline
        self.provider = pipeline_config.llm_provider or "openai"
        self.api_key = pipeline_config.llm_api_key
        self.model = pipeline_config.llm_model or "gpt-4o-mini"

        if not self.api_key:
            raise ValueError("LLM_API_KEY is required for LLM enrichment")

        # Initialize OpenAI client
        self.client = openai.OpenAI(api_key=self.api_key)

    def process(self, cve: CVE) -> CVE:
        """
        Enrich CVE with LLM-generated insights.

        Args:
            cve: CVE to enrich

        Returns:
            CVE with enriched fields populated
        """
        self.logger.debug("Enriching CVE with LLM", cve_id=cve.cve_id)

        try:
            prompt = self._build_prompt(cve)
            response = self._call_llm(prompt)

            # Parse structured response
            enrichment = self._parse_response(response)

            # Update CVE with enriched data
            cve_dict = cve.__dict__.copy()
            cve_dict.update(
                {
                    "enriched_summary": enrichment.get("summary"),
                    "risk_assessment": enrichment.get("risk_assessment"),
                    "recommended_actions": enrichment.get("recommended_actions"),
                }
            )

            enriched_cve = CVE(**cve_dict)

            self.logger.debug("CVE enrichment complete", cve_id=cve.cve_id)
            return enriched_cve

        except Exception as e:
            self.logger.error("LLM enrichment failed", cve_id=cve.cve_id, error=str(e))
            # Return original CVE on failure
            return cve

    def _build_prompt(self, cve: CVE) -> str:
        """
        Build LLM prompt for CVE enrichment.

        Args:
            cve: CVE to analyze

        Returns:
            Formatted prompt string
        """
        return f"""Analyze this CVE and provide structured insights.

CVE ID: {cve.cve_id}
Description: {cve.description}
Severity: {cve.severity or "Unknown"}
CVSS Score: {cve.cvss_score or "N/A"}
Attack Vector: {cve.attack_vector or "Unknown"}
Affected Products: {", ".join(cve.affected_products[:5]) if cve.affected_products else "Unknown"}
Affected Vendors: {", ".join(cve.affected_vendors[:5]) if cve.affected_vendors else "Unknown"}

Provide a JSON response with the following fields:
- summary: A 1-2 sentence concise summary of the vulnerability
- risk_assessment: Brief assessment of the risk level and potential impact
- recommended_actions: Specific actions organizations should take

Keep responses concise and technical. Output only valid JSON."""

    def _call_llm(self, prompt: str) -> str:
        """
        Call LLM API with prompt.

        Args:
            prompt: Formatted prompt

        Returns:
            LLM response text
        """
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst specializing in vulnerability assessment.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=500,
        )

        return response.choices[0].message.content

    def _parse_response(self, response: str) -> dict:
        """
        Parse LLM response into structured data.

        Args:
            response: Raw LLM response

        Returns:
            Dictionary with enrichment fields
        """
        try:
            # Try to parse as JSON
            return json.loads(response)
        except json.JSONDecodeError:
            # Fallback: treat entire response as summary
            return {
                "summary": response[:200],
                "risk_assessment": None,
                "recommended_actions": None,
            }

    def get_step_name(self) -> str:
        return f"LLMEnricher(provider={self.provider}, model={self.model})"
