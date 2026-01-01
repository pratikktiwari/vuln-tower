"""
Core module for CVE Notifier.

Contains configuration, logging, secrets management, and execution context.
"""

from .config import Config
from .logger import create_logger, StructuredLogger
from .scheduler_context import SchedulerContext

__all__ = ["Config", "create_logger", "StructuredLogger", "SchedulerContext"]
