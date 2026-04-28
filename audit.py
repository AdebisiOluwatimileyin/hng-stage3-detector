# audit.py — Structured audit logging
# Format: [timestamp] ACTION ip | condition | rate | baseline | duration

import logging
from datetime import datetime
from config import AUDIT_LOG_FILE

# Set up the audit logger
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

# File handler — writes to audit.log
file_handler = logging.FileHandler(AUDIT_LOG_FILE)
file_handler.setLevel(logging.INFO)

# Format: just the message (we build our own format)
formatter = logging.Formatter("%(message)s")
file_handler.setFormatter(formatter)
audit_logger.addHandler(file_handler)

# Also print to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
audit_logger.addHandler(console_handler)


def log_action(action, ip=None, condition=None, rate=None, baseline=None, duration=None):
    """
    Write a structured audit log entry.
    
    Example output:
    [2026-04-25T21:17:33] BAN 1.2.3.4 | z-score=4.2 | rate=45.2 | baseline=8.1 | duration=600s
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    
    parts = [f"[{timestamp}] {action}"]
    
    if ip:
        parts.append(ip)
    
    details = []
    if condition:
        details.append(f"condition={condition}")
    if rate is not None:
        details.append(f"rate={rate:.2f}")
    if baseline is not None:
        details.append(f"baseline={baseline:.2f}")
    if duration is not None:
        details.append(f"duration={duration}s")
    
    if details:
        parts.append(" | ".join(details))
    
    message = " | ".join(parts)
    audit_logger.info(message)
