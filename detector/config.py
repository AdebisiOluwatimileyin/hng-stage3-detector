# config.py — All configuration in one place
import os

# ─── Log File ───────────────────────────────────────────────────
LOG_FILE = "/var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log"

# ─── Sliding Window ─────────────────────────────────────────────
WINDOW_SECONDS = 60
GLOBAL_WINDOW_SECONDS = 60

# ─── Baseline ───────────────────────────────────────────────────
BASELINE_WINDOW_MINUTES = 30
BASELINE_RECALC_INTERVAL = 60

# ─── Detection Thresholds ────────────────────────────────────────
ZSCORE_THRESHOLD = 3.0
RATE_MULTIPLIER = 5.0
ERROR_RATE_MULTIPLIER = 3.0

# ─── Blocking ───────────────────────────────────────────────────
BLOCK_CHECK_INTERVAL = 10

# ─── Auto-Unban Backoff Schedule (seconds) ───────────────────────
UNBAN_SCHEDULE = [
    600,    # 10 minutes
    1800,   # 30 minutes
    7200,   # 2 hours
    -1      # permanent
]

# ─── Slack ───────────────────────────────────────────────────────
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SLACK_ENABLED = bool(SLACK_WEBHOOK_URL)

# ─── Dashboard ───────────────────────────────────────────────────
DASHBOARD_PORT = 5000
DASHBOARD_REFRESH_SECONDS = 3

# ─── Audit Log ───────────────────────────────────────────────────
AUDIT_LOG_FILE = "/opt/hng-detector/logs/audit.log"
