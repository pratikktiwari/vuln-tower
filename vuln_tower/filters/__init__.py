"""
CVE filter implementations.

Provides pluggable filters for CVE evaluation.
"""

from typing import List

from vuln_tower.core import Config
from .base import CVEFilter
from .cvss_filter import CVSSFilter
from .keyword_filter import KeywordFilter
from .product_vendor_filter import ProductFilter, VendorFilter, AttackVectorFilter


def create_filters(config: Config) -> List[CVEFilter]:
    """
    Factory function to create filters from configuration.

    Args:
        config: Application configuration

    Returns:
        List of active CVEFilter instances
    """
    filters: List[CVEFilter] = []
    filter_config = config.filter

    # Add CVSS filter if min score is set
    if filter_config.min_cvss_score > 0.0:
        filters.append(CVSSFilter(filter_config.min_cvss_score))

    # Add keyword filter if keywords are specified
    if filter_config.keywords:
        filters.append(KeywordFilter(filter_config.keywords))

    # Add product filter if products are specified
    if filter_config.products:
        filters.append(ProductFilter(filter_config.products))

    # Add vendor filter if vendors are specified
    if filter_config.vendors:
        filters.append(VendorFilter(filter_config.vendors))

    # Add attack vector filter if specified
    if filter_config.attack_vector:
        filters.append(AttackVectorFilter(filter_config.attack_vector))

    return filters


__all__ = [
    "CVEFilter",
    "CVSSFilter",
    "KeywordFilter",
    "ProductFilter",
    "VendorFilter",
    "AttackVectorFilter",
    "create_filters",
]
