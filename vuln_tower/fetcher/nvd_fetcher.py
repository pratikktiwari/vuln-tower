"""
NVD (National Vulnerability Database) CVE fetcher.

Fetches CVEs from the NIST NVD API (v2.0).
"""

from datetime import datetime, timedelta
from typing import List, Optional
import requests

from vuln_tower.core import Config, StructuredLogger
from vuln_tower.models import CVE
from .base import CVEFetcher


class NVDFetcher(CVEFetcher):
    """
    Fetches CVEs from the NIST National Vulnerability Database.

    Uses NVD API v2.0: https://nvd.nist.gov/developers/vulnerabilities
    """

    API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, config: Config, logger: StructuredLogger):
        """
        Initialize NVD fetcher.

        Args:
            config: Application configuration
            logger: Structured logger instance
        """
        self.config = config
        self.logger = logger
        self.api_key = config.nvd.api_key
        self.fetch_window_minutes = config.nvd.fetch_window_minutes
        self.max_results = config.nvd.max_results_per_run
        self.timeout = config.nvd.request_timeout

    def fetch(self) -> List[CVE]:
        """
        Fetch recent CVEs from NVD.

        Returns:
            List of CVE objects published within the configured time window
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=self.fetch_window_minutes)

        self.logger.info(
            "Fetching CVEs from NVD",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            window_minutes=self.fetch_window_minutes,
        )

        params = {
            "pubStartDate": self._format_datetime(start_time),
            "pubEndDate": self._format_datetime(end_time),
            "resultsPerPage": min(self.max_results, 2000),  # NVD max is 2000
        }

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(
                self.API_BASE, params=params, headers=headers, timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            self.logger.info("Fetched CVEs from NVD", count=len(vulnerabilities))

            cves = []
            for item in vulnerabilities[: self.max_results]:
                try:
                    cve = self._parse_cve(item)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    self.logger.error(
                        "Failed to parse CVE",
                        error=str(e),
                        item=item.get("cve", {}).get("id", "unknown"),
                    )

            return cves

        except requests.RequestException as e:
            self.logger.error("Failed to fetch from NVD", error=str(e))
            raise RuntimeError(f"NVD API request failed: {e}")

    def _parse_cve(self, vulnerability: dict) -> Optional[CVE]:
        """
        Parse NVD vulnerability JSON into CVE domain object.

        Args:
            vulnerability: Raw vulnerability data from NVD API

        Returns:
            CVE object or None if parsing fails
        """
        try:
            cve_data = vulnerability.get("cve", {})
            cve_id = cve_data.get("id")

            if not cve_id:
                return None

            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract dates
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", published)

            # Extract CVSS metrics
            metrics = cve_data.get("metrics", {})
            cvss_score = None
            cvss_vector = None
            severity = None
            attack_vector = None
            attack_complexity = None

            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    cvss_data = metric.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    severity = metric.get("baseSeverity") or cvss_data.get(
                        "baseSeverity"
                    )
                    attack_vector = cvss_data.get("attackVector")
                    attack_complexity = cvss_data.get("attackComplexity")
                    break

            # Extract affected vendors and products
            configurations = cve_data.get("configurations", [])
            affected_vendors = set()
            affected_products = set()

            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            if vendor != "*":
                                affected_vendors.add(vendor)
                            if product != "*":
                                affected_products.add(product)

            # Extract references
            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url")
                if url:
                    references.append(url)

            # Extract CWE IDs
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value.startswith("CWE-"):
                        cwe_ids.append(value)

            return CVE(
                cve_id=cve_id,
                description=description,
                published_date=self._parse_datetime(published),
                last_modified_date=self._parse_datetime(modified),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=severity,
                affected_vendors=list(affected_vendors),
                affected_products=list(affected_products),
                references=references,
                cwe_ids=cwe_ids,
                attack_vector=attack_vector,
                attack_complexity=attack_complexity,
            )

        except Exception as e:
            self.logger.error("CVE parsing error", error=str(e))
            return None

    @staticmethod
    def _format_datetime(dt: datetime) -> str:
        """Format datetime for NVD API (ISO 8601)."""
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    @staticmethod
    def _parse_datetime(date_str: str) -> datetime:
        """Parse datetime from NVD API response."""
        # NVD uses ISO 8601 format
        if "." in date_str:
            date_str = date_str.split(".")[0]
        return datetime.fromisoformat(date_str.replace("Z", ""))
