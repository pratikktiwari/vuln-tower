"""
Pipeline middleware for CVE enrichment.

Provides a composable pipeline for transforming and enriching CVEs.
"""

from typing import List

from vuln_tower.core import Config, StructuredLogger
from vuln_tower.models import CVE
from .base import PipelineStep
from .llm_enricher import LLMEnricher


class Pipeline:
    """
    Composable pipeline for CVE processing.

    Executes a series of steps on each CVE, allowing for enrichment,
    transformation, and validation.
    """

    def __init__(self, steps: List[PipelineStep], logger: StructuredLogger):
        """
        Initialize pipeline.

        Args:
            steps: List of pipeline steps to execute in order
            logger: Structured logger instance
        """
        self.steps = steps
        self.logger = logger

    def process(self, cve: CVE) -> CVE:
        """
        Process CVE through all pipeline steps.

        Args:
            cve: CVE to process

        Returns:
            Processed CVE
        """
        current_cve = cve

        for step in self.steps:
            try:
                self.logger.debug(
                    "Executing pipeline step",
                    step=step.get_step_name(),
                    cve_id=cve.cve_id,
                )
                current_cve = step.process(current_cve)
            except Exception as e:
                self.logger.error(
                    "Pipeline step failed",
                    step=step.get_step_name(),
                    cve_id=cve.cve_id,
                    error=str(e),
                )
                # Continue with next step even if this one fails

        return current_cve


def create_pipeline(config: Config, logger: StructuredLogger) -> Pipeline:
    """
    Factory function to create pipeline from configuration.

    Args:
        config: Application configuration
        logger: Structured logger instance

    Returns:
        Configured Pipeline instance
    """
    steps: List[PipelineStep] = []

    if not config.pipeline.enable_pipeline:
        return Pipeline(steps, logger)

    # Parse configured pipeline steps
    for step_name in config.pipeline.pipeline_steps:
        step_name = step_name.lower().strip()

        if step_name == "llm" or step_name == "llm_enricher":
            try:
                steps.append(LLMEnricher(config, logger))
            except Exception as e:
                logger.error("Failed to initialize LLM enricher", error=str(e))
        else:
            logger.warning(f"Unknown pipeline step: {step_name}")

    logger.info("Pipeline initialized", steps=[step.get_step_name() for step in steps])

    return Pipeline(steps, logger)


__all__ = ["PipelineStep", "Pipeline", "LLMEnricher", "create_pipeline"]
