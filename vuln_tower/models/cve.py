"""
CVE domain model.

Represents a Common Vulnerabilities and Exposures (CVE) entry
with all relevant metadata.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List


@dataclass
class CVE:
    """
    Domain model for a CVE vulnerability.
    
    Contains core CVE information as well as optional enriched data
    from middleware pipelines.
    """
    
    # Core CVE data
    cve_id: str
    description: str
    published_date: datetime
    last_modified_date: datetime
    
    # Severity metrics
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity: Optional[str]  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Affected products
    affected_vendors: List[str]
    affected_products: List[str]
    
    # References and details
    references: List[str]
    cwe_ids: List[str]
    
    # Attack characteristics
    attack_vector: Optional[str]  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity: Optional[str]
    
    # Optional enriched data (added by pipeline)
    enriched_summary: Optional[str] = None
    risk_assessment: Optional[str] = None
    recommended_actions: Optional[str] = None
    
    def __post_init__(self):
        """Validate and normalize data after initialization."""
        if not self.cve_id:
            raise ValueError("CVE ID cannot be empty")
        
        # Normalize CVE ID format
        if not self.cve_id.startswith("CVE-"):
            raise ValueError(f"Invalid CVE ID format: {self.cve_id}")
        
        # Ensure lists are not None
        if self.affected_vendors is None:
            object.__setattr__(self, 'affected_vendors', [])
        if self.affected_products is None:
            object.__setattr__(self, 'affected_products', [])
        if self.references is None:
            object.__setattr__(self, 'references', [])
        if self.cwe_ids is None:
            object.__setattr__(self, 'cwe_ids', [])
    
    @property
    def nvd_url(self) -> str:
        """Generate the NVD detail URL for this CVE."""
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"
    
    def matches_keywords(self, keywords: List[str]) -> bool:
        """
        Check if CVE description matches any of the given keywords.
        
        Args:
            keywords: List of keywords to match (case-insensitive)
            
        Returns:
            True if any keyword is found in description
        """
        if not keywords:
            return True
        
        description_lower = self.description.lower()
        return any(keyword.lower() in description_lower for keyword in keywords)
    
    def matches_products(self, products: List[str]) -> bool:
        """
        Check if CVE affects any of the specified products.
        
        Args:
            products: List of product names to match (case-insensitive)
            
        Returns:
            True if any product is affected
        """
        if not products:
            return True
        
        affected_lower = [p.lower() for p in self.affected_products]
        return any(
            product.lower() in affected_lower
            for product in products
        )
    
    def matches_vendors(self, vendors: List[str]) -> bool:
        """
        Check if CVE affects any of the specified vendors.
        
        Args:
            vendors: List of vendor names to match (case-insensitive)
            
        Returns:
            True if any vendor is affected
        """
        if not vendors:
            return True
        
        affected_lower = [v.lower() for v in self.affected_vendors]
        return any(
            vendor.lower() in affected_lower
            for vendor in vendors
        )
    
    def to_dict(self) -> dict:
        """Convert CVE to dictionary representation."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "published_date": self.published_date.isoformat(),
            "last_modified_date": self.last_modified_date.isoformat(),
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "affected_vendors": self.affected_vendors,
            "affected_products": self.affected_products,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "enriched_summary": self.enriched_summary,
            "risk_assessment": self.risk_assessment,
            "recommended_actions": self.recommended_actions
        }
