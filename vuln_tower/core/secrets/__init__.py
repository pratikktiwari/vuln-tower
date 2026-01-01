"""
Secret management module.

Provides pluggable secret providers for different backends.
"""

from .base import SecretProvider
from .env_provider import EnvSecretProvider

__all__ = ["SecretProvider", "EnvSecretProvider"]
