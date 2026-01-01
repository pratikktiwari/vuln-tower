"""
Environment variable-based secret provider.

Reads secrets from the process environment.
"""

import os
import dotenv
from typing import Optional

from .base import SecretProvider


class EnvSecretProvider(SecretProvider):
    """
    Loads secrets from environment variables.

    This is the default provider and works in most deployment scenarios.
    """

    def __init__(self):
        # Load .env file if present
        dotenv.load_dotenv()

    def get_secret(self, key: str) -> Optional[str]:
        """
        Retrieve a secret from environment variables.

        Args:
            key: The environment variable name

        Returns:
            The value if the variable exists, None otherwise
        """
        return os.getenv(key)

    def get_required_secret(self, key: str) -> str:
        """
        Retrieve a required secret from environment variables.

        Args:
            key: The environment variable name

        Returns:
            The secret value

        Raises:
            ValueError: If the environment variable is not set
        """
        value = os.getenv(key)
        if value is None:
            raise ValueError(
                f"Required secret '{key}' not found in environment variables"
            )
        return value
