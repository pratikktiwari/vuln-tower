"""
Product and vendor filters.

Filters CVEs based on affected products and vendors.
"""

from typing import List

from vuln_tower.models import CVE
from .base import CVEFilter


class ProductFilter(CVEFilter):
    """
    Filter CVEs by affected products.

    If product list is empty, all CVEs pass.
    If products are specified, CVE must affect at least one.
    """

    def __init__(self, products: List[str]):
        """
        Initialize product filter.

        Args:
            products: List of product names to match (case-insensitive)
        """
        self.products = products

    def should_notify(self, cve: CVE) -> bool:
        """
        Check if CVE affects any of the specified products.

        Args:
            cve: CVE to evaluate

        Returns:
            True if any product is affected, or if product list is empty
        """
        if not self.products:
            return True

        return cve.matches_products(self.products)

    def get_filter_name(self) -> str:
        product_str = ", ".join(self.products[:3])
        if len(self.products) > 3:
            product_str += "..."
        return f"ProductFilter(products=[{product_str}])"


class VendorFilter(CVEFilter):
    """
    Filter CVEs by affected vendors.

    If vendor list is empty, all CVEs pass.
    If vendors are specified, CVE must affect at least one.
    """

    def __init__(self, vendors: List[str]):
        """
        Initialize vendor filter.

        Args:
            vendors: List of vendor names to match (case-insensitive)
        """
        self.vendors = vendors

    def should_notify(self, cve: CVE) -> bool:
        """
        Check if CVE affects any of the specified vendors.

        Args:
            cve: CVE to evaluate

        Returns:
            True if any vendor is affected, or if vendor list is empty
        """
        if not self.vendors:
            return True

        return cve.matches_vendors(self.vendors)

    def get_filter_name(self) -> str:
        vendor_str = ", ".join(self.vendors[:3])
        if len(self.vendors) > 3:
            vendor_str += "..."
        return f"VendorFilter(vendors=[{vendor_str}])"


class AttackVectorFilter(CVEFilter):
    """
    Filter CVEs by attack vector.

    Attack vectors: NETWORK, ADJACENT, LOCAL, PHYSICAL
    """

    def __init__(self, attack_vector: str):
        """
        Initialize attack vector filter.

        Args:
            attack_vector: Required attack vector (case-insensitive)
        """
        self.attack_vector = attack_vector.upper()

    def should_notify(self, cve: CVE) -> bool:
        """
        Check if CVE has the specified attack vector.

        Args:
            cve: CVE to evaluate

        Returns:
            True if attack vector matches or is unavailable
        """
        if cve.attack_vector is None:
            return True  # Allow CVEs without attack vector data

        return cve.attack_vector.upper() == self.attack_vector

    def get_filter_name(self) -> str:
        return f"AttackVectorFilter(vector={self.attack_vector})"
