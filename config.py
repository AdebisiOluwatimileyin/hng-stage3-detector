# config.py — All configuration in one place

# ─── Log File ───────────────────────────────────────────────────
LOG_FILE = "/var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log"

# ─── Sliding Window ─────────────────────────────────────────────
WINDOW_SECONDS = 60          # Track requests in last 60 seconds
GLOBAL_WINDOW_SECONDS = 60   # Global window same size

# ─── Baseline ───────────────────────────────────────────────────
BASELINE_WINDOW_MINUTES = 30  # Rolling 30-minute history
BASELINE_RECALC_INTERVAL = 60 # Recalculate every 60 seconds

# ─── Detection Thresholds ────────────────────────────────────────
ZSCORE_THRESHOLD = 3.0        # Z-score above this = anomaly
RATE_MULTIPLIER = 5.0         # Rate > 5x baseline = anomaly
ERROR_RATE_MULTIPLIER = 3.0   # Error rate > 3x baseline = tighten

# ─── Blocking ───────────────────────────────────────────────────
BLOCK_CHECK_INTERVAL = 10     # Check for blocks every 10 seconds

# ─── Auto-Unban Backoff Schedule (seconds) ───────────────────────
UNBAN_SCHEDULE = [
    600,    # 10 minutes
    1800,   # 30 minutes
    7200,   # 2 hours
    -1      # permanent (-1 means never unban)
]

# ─── Slack ───────────────────────────────────────────────────────
import os
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SLACK_ENABLED = bool(SLACK_WEBHOOK_URL)

# ─── Dashboard ───────────────────────────────────────────────────
DASHBOARD_PORT = 5000
DASHBOARD_REFRESH_SECONDS = 3

# ─── Audit Log ───────────────────────────────────────────────────
AUDIT_LOG_FILE = "/opt/hng-detector/logs/audit.log"

