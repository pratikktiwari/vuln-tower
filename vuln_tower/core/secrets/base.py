"""
Abstract base class for secret providers.

Defines the interface for loading secrets from various backends
(environment variables, cloud secret stores, etc.).
"""

from abc import ABC, abstractmethod
from typing import Optional


class SecretProvider(ABC):
    """
    Abstract interface for secret retrieval.
    
    Implementations must provide a method to fetch secrets by key,
    returning None if the secret doesn't exist.
    """
    
    @abstractmethod
    def get_secret(self, key: str) -> Optional[str]:
        """
        Retrieve a secret value by key.
        
        Args:
            key: The secret identifier
            
        Returns:
            The secret value if found, None otherwise
        """
        pass
    
    @abstractmethod
    def get_required_secret(self, key: str) -> str:
        """
        Retrieve a required secret, raising an exception if not found.
        
        Args:
            key: The secret identifier
            
        Returns:
            The secret value
            
        Raises:
            ValueError: If the secret is not found
        """
        pass
