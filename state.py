# state.py — Shared state between all modules
# Think of this as the central memory of the system

import threading
from collections import defaultdict, deque

# ─── Thread Lock ─────────────────────────────────────────────────
# Prevents two modules from modifying state at the same time
lock = threading.Lock()

# ─── Sliding Windows ─────────────────────────────────────────────
# Per-IP request timestamps (last 60 seconds)
# Example: ip_window["1.2.3.4"] = deque([1714000000.1, 1714000001.5, ...])
ip_window = defaultdict(deque)

# Global request timestamps (last 60 seconds)
global_window = deque()

# ─── Baseline Data ───────────────────────────────────────────────
# Per-hour request rate buckets for last 30 minutes
# Example: baseline_buckets[14] = [10.2, 11.5, 9.8, ...]  (hour 14)
baseline_buckets = defaultdict(list)

# Calculated baseline stats
baseline_mean = 0.0
baseline_stddev = 0.0

# ─── Banned IPs ──────────────────────────────────────────────────
# Format: {"1.2.3.4": {"banned_at": 1714000000, "level": 0, "unban_at": 1714000600}}
banned_ips = {}

# ─── Error Tracking ──────────────────────────────────────────────
# Per-IP error counts in current window
ip_error_window = defaultdict(deque)

# ─── System Stats ────────────────────────────────────────────────
start_time = None          # When the daemon started
total_requests = 0         # Total requests seen
total_blocked = 0          # Total IPs blocked
current_rps = 0.0          # Current requests per second (global)

# ─── Top IPs ─────────────────────────────────────────────────────
# Running count of requests per IP
ip_request_counts = defaultdict(int)
