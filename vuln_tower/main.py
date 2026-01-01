#!/usr/bin/env python3
"""
Vuln Tower - Main Entrypoint

CCVE monitoring system that fetches vulnerabilities from NVD,
applies filters, enriches data through optional pipelines, and sends alerts
to configured notification channels.

Execution model: Run → Process → Notify → Exit
"""

import sys
from typing import List

from vuln_tower.core import Config, create_logger, SchedulerContext
from vuln_tower.storage import create_storage
from vuln_tower.fetcher import NVDFetcher
from vuln_tower.filters import create_filters
from vuln_tower.pipeline import create_pipeline
from vuln_tower.notifier import create_notifiers
from vuln_tower.models import CVE


def main():
    """Main execution flow."""

    # Load configuration
    try:
        config = Config.load()
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Initialize logger
    logger = create_logger("vuln_tower", config.general.log_level)

    # Create execution context
    context = SchedulerContext.create(config.general.run_mode)
    logger.info(
        "Starting CVE Notifier", run_id=context.run_id, run_mode=context.run_mode
    )

    try:
        # Initialize storage backend
        logger.info("Initializing storage backend", db_type=config.database.db_type)
        storage = create_storage(config)

        # Initialize fetcher
        logger.info("Initializing CVE fetcher")
        fetcher = NVDFetcher(config, logger)

        # Initialize filters
        logger.info("Initializing filters")
        filters = create_filters(config)
        logger.info("Active filters", count=len(filters))

        # Initialize pipeline
        logger.info("Initializing pipeline")
        pipeline = create_pipeline(config, logger)

        # Initialize notifiers
        logger.info("Initializing notifiers")
        notifiers = create_notifiers(config, logger)

        if not notifiers:
            logger.warning("No notifiers configured - CVEs will be logged only")

        # Fetch CVEs
        logger.info("Fetching CVEs from NVD")
        all_cves = fetcher.fetch()
        logger.info("Fetched CVEs", count=len(all_cves))

        # Deduplicate against processed CVEs
        new_cves = []
        for cve in all_cves:
            if not storage.is_processed(cve.cve_id):
                new_cves.append(cve)
            else:
                logger.debug("CVE already processed", cve_id=cve.cve_id)

        logger.info("New CVEs after deduplication", count=len(new_cves))

        if not new_cves:
            logger.info("No new CVEs to process")
            context.complete()
            storage.close()
            return

        # Apply filters
        filtered_cves = apply_filters(new_cves, filters, logger)
        logger.info("CVEs after filtering", count=len(filtered_cves))

        if not filtered_cves:
            logger.info("No CVEs passed filters")
            # Mark all as processed even though they didn't pass filters
            for cve in new_cves:
                storage.mark_processed(cve)
            context.complete()
            storage.close()
            return

        # Apply pipeline enrichment
        enriched_cves = apply_pipeline(filtered_cves, pipeline, logger)
        logger.info("CVEs after pipeline enrichment", count=len(enriched_cves))

        # Send notifications
        notify_cves(enriched_cves, notifiers, logger)

        # Mark CVEs as processed
        for cve in new_cves:
            storage.mark_processed(cve)

        logger.info(
            "CVE processing complete",
            total_fetched=len(all_cves),
            new_cves=len(new_cves),
            filtered=len(filtered_cves),
            notified=len(enriched_cves),
        )

        # Update last run metadata
        storage.set_metadata("last_run", context.start_time.isoformat())
        storage.set_metadata("last_run_count", str(len(enriched_cves)))

        # Complete execution
        context.complete()
        logger.info("Execution complete", duration_seconds=context.duration_seconds)

        storage.close()

    except Exception as e:
        logger.error("Execution failed", error=str(e), error_type=type(e).__name__)
        context.complete()
        sys.exit(1)


def apply_filters(cves: List[CVE], filters: List, logger) -> List[CVE]:
    """
    Apply all filters to CVE list.

    Args:
        cves: List of CVEs to filter
        filters: List of filter instances
        logger: Logger instance

    Returns:
        Filtered list of CVEs
    """
    if not filters:
        return cves

    filtered = []

    for cve in cves:
        passes_all = True

        for f in filters:
            if not f.should_notify(cve):
                logger.debug(
                    "CVE filtered out", cve_id=cve.cve_id, filter=f.get_filter_name()
                )
                passes_all = False
                break

        if passes_all:
            filtered.append(cve)

    return filtered


def apply_pipeline(cves: List[CVE], pipeline, logger) -> List[CVE]:
    """
    Apply pipeline enrichment to CVEs.

    Args:
        cves: List of CVEs to enrich
        pipeline: Pipeline instance
        logger: Logger instance

    Returns:
        List of enriched CVEs
    """
    enriched = []

    for cve in cves:
        try:
            enriched_cve = pipeline.process(cve)
            enriched.append(enriched_cve)
        except Exception as e:
            logger.error(
                "Pipeline processing failed for CVE", cve_id=cve.cve_id, error=str(e)
            )
            # Include original CVE even if enrichment fails
            enriched.append(cve)

    return enriched


def notify_cves(cves: List[CVE], notifiers: List, logger):
    """
    Send CVEs to all configured notifiers.

    Args:
        cves: List of CVEs to notify
        notifiers: List of notifier instances
        logger: Logger instance
    """
    if not notifiers:
        logger.warning("No notifiers available")
        return

    for notifier in notifiers:
        try:
            notifier.send(cves)
            logger.info(
                "Notifications sent",
                notifier=notifier.get_notifier_name(),
                count=len(cves),
            )
        except Exception as e:
            logger.error(
                "Notifier failed", notifier=notifier.get_notifier_name(), error=str(e)
            )


if __name__ == "__main__":
    main()
