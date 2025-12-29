"""
Logging configuration module.

Sets up logging with Rich console output and file rotation.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console

# Global console instance
console = Console()


def setup_logging(
    level: str = "INFO",
    log_to_file: bool = True,
    log_file: str = "logs/sentinelscapyscan.log",
    max_log_size: int = 10485760,  # 10 MB
    backup_count: int = 5,
    rich_tracebacks: bool = True
) -> None:
    """
    Setup logging configuration with Rich console output and file rotation.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Enable logging to file
        log_file: Path to log file
        max_log_size: Maximum log file size in bytes
        backup_count: Number of backup log files to keep
        rich_tracebacks: Enable Rich tracebacks
    """
    # Convert level string to logging level
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Rich console handler
    console_handler = RichHandler(
        console=console,
        rich_tracebacks=rich_tracebacks,
        tracebacks_show_locals=True,
        markup=True,
        show_time=True,
        show_path=True
    )
    console_handler.setLevel(log_level)
    
    # Console format
    console_format = "%(message)s"
    console_handler.setFormatter(logging.Formatter(console_format))
    
    root_logger.addHandler(console_handler)
    
    # File handler (if enabled)
    if log_to_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_log_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        
        # File format
        file_format = (
            "%(asctime)s - %(name)s - %(levelname)s - "
            "%(filename)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(logging.Formatter(file_format))
        
        root_logger.addHandler(file_handler)
    
    # Set third-party loggers to WARNING
    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    logging.info(f"Logging initialized at {level} level")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_log_level(level: str) -> None:
    """
    Change the logging level at runtime.
    
    Args:
        level: New logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_level)
    
    for handler in logging.getLogger().handlers:
        handler.setLevel(log_level)
    
    logging.info(f"Log level changed to {level}")


def disable_scapy_warnings() -> None:
    """Disable Scapy warnings and verbose output."""
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy").setLevel(logging.ERROR)
    
    # Suppress Scapy warnings
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)


class ScanProgressLogger:
    """
    Context manager for logging scan progress with Rich.
    """
    
    def __init__(self, description: str, total: Optional[int] = None):
        """
        Initialize progress logger.
        
        Args:
            description: Description of the task
            total: Total number of items (optional)
        """
        self.description = description
        self.total = total
        self.current = 0
        self.logger = get_logger(__name__)
    
    def __enter__(self):
        """Enter context."""
        self.logger.info(f"Starting: {self.description}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context."""
        if exc_type is None:
            self.logger.info(f"Completed: {self.description}")
        else:
            self.logger.error(f"Failed: {self.description} - {exc_val}")
        return False
    
    def update(self, increment: int = 1, message: Optional[str] = None):
        """
        Update progress.
        
        Args:
            increment: Number of items completed
            message: Optional progress message
        """
        self.current += increment
        
        if message:
            self.logger.debug(message)
        
        if self.total:
            progress = (self.current / self.total) * 100
            self.logger.debug(
                f"{self.description}: {self.current}/{self.total} ({progress:.1f}%)"
            )


def log_scan_summary(
    total_hosts: int,
    reachable_hosts: int,
    total_open_ports: int,
    scan_duration: float
) -> None:
    """
    Log a formatted scan summary.
    
    Args:
        total_hosts: Total number of hosts scanned
        reachable_hosts: Number of reachable hosts
        total_open_ports: Total number of open ports found
        scan_duration: Total scan duration in seconds
    """
    logger = get_logger(__name__)
    
    console.print("\n" + "="*60, style="bold blue")
    console.print("SCAN SUMMARY", style="bold blue", justify="center")
    console.print("="*60 + "\n", style="bold blue")
    
    console.print(f"[bold]Total Hosts Scanned:[/bold] {total_hosts}")
    console.print(f"[bold]Reachable Hosts:[/bold] {reachable_hosts}")
    console.print(f"[bold]Total Open Ports:[/bold] {total_open_ports}")
    console.print(f"[bold]Scan Duration:[/bold] {scan_duration:.2f}s")
    
    console.print("\n" + "="*60 + "\n", style="bold blue")


def log_error_with_context(error: Exception, context: str) -> None:
    """
    Log an error with context information.
    
    Args:
        error: Exception object
        context: Context description
    """
    logger = get_logger(__name__)
    logger.error(f"{context}: {type(error).__name__}: {error}", exc_info=True)
