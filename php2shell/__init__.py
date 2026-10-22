"""PHP2Shell Scanner."""

from .core import (
    CVE_IDS,
    FIXED_VERSIONS,
    ScanConfig,
    ScanJob,
    classify_php_version,
    parse_server_text,
    parse_target_text,
    scan_job,
)

__version__ = "1.0.2"

__all__ = [
    "CVE_IDS",
    "FIXED_VERSIONS",
    "ScanConfig",
    "ScanJob",
    "classify_php_version",
    "parse_server_text",
    "parse_target_text",
    "scan_job",
]
