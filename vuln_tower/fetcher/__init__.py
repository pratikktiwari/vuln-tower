"""
CVE fetcher implementations.
"""

from .base import CVEFetcher
from .nvd_fetcher import NVDFetcher

__all__ = ["CVEFetcher", "NVDFetcher"]
