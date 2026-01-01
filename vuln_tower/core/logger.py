"""
Structured logging configuration.

Provides consistent, structured logging across the application.
"""

import logging
import sys
from typing import Optional


class StructuredLogger:
    """
    Wrapper around Python's logging module with structured output.
    
    Ensures consistent log formatting and context injection.
    """
    
    def __init__(self, name: str, level: str = "INFO"):
        """
        Initialize logger.
        
        Args:
            name: Logger name (typically module or component name)
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def debug(self, message: str, **context):
        """Log debug message with optional context."""
        self._log(logging.DEBUG, message, context)
    
    def info(self, message: str, **context):
        """Log info message with optional context."""
        self._log(logging.INFO, message, context)
    
    def warning(self, message: str, **context):
        """Log warning message with optional context."""
        self._log(logging.WARNING, message, context)
    
    def error(self, message: str, **context):
        """Log error message with optional context."""
        self._log(logging.ERROR, message, context)
    
    def critical(self, message: str, **context):
        """Log critical message with optional context."""
        self._log(logging.CRITICAL, message, context)
    
    def _log(self, level: int, message: str, context: dict):
        """Internal logging method with context formatting."""
        if context:
            context_str = " | ".join(f"{k}={v}" for k, v in context.items())
            full_message = f"{message} | {context_str}"
        else:
            full_message = message
        
        self.logger.log(level, full_message)


def create_logger(name: str, level: str = "INFO") -> StructuredLogger:
    """
    Factory function to create a structured logger.
    
    Args:
        name: Logger name
        level: Log level
        
    Returns:
        StructuredLogger instance
    """
    return StructuredLogger(name, level)
