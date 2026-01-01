"""
Scheduler execution context.

Tracks metadata about the current execution run, useful for
debugging, auditing, and understanding cron behavior.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import platform
import socket


@dataclass
class SchedulerContext:
    """
    Execution context for a scheduler run.
    
    Captures environment and timing information about the current execution.
    """
    run_id: str
    start_time: datetime
    hostname: str
    platform: str
    run_mode: str
    end_time: Optional[datetime] = None
    
    @staticmethod
    def create(run_mode: str) -> "SchedulerContext":
        """
        Create a new scheduler context for the current run.
        
        Args:
            run_mode: Execution mode (cron, ci, local, etc.)
            
        Returns:
            SchedulerContext instance
        """
        timestamp = datetime.utcnow()
        run_id = timestamp.strftime("%Y%m%d_%H%M%S")
        
        return SchedulerContext(
            run_id=run_id,
            start_time=timestamp,
            hostname=socket.gethostname(),
            platform=platform.system(),
            run_mode=run_mode
        )
    
    def complete(self):
        """Mark the execution as complete."""
        object.__setattr__(self, 'end_time', datetime.utcnow())
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate execution duration if completed."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    def to_dict(self) -> dict:
        """Convert context to dictionary for logging."""
        return {
            "run_id": self.run_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "hostname": self.hostname,
            "platform": self.platform,
            "run_mode": self.run_mode
        }
