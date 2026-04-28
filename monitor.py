# monitor.py — Continuous Nginx log tailer and parser
#
# CONCEPT: This is the entry point of all data.
# Like a security camera feed — it watches the log file
# continuously and processes every new line in real time.
#
# HOW IT WORKS:
# 1. Open the log file
# 2. Seek to the end (ignore old entries)
# 3. Wait for new lines
# 4. Parse each JSON line
# 5. Pass data to sliding window and detector

import json
import time
import os
import threading

import state
from config import LOG_FILE
from sliding_window import record_request, record_error
from detector import check_ip, check_global
from blocker import block_ip
from notifier import send_global_anomaly_alert
from audit import log_action


def parse_log_line(line: str) -> dict | None:
    """
    Parse a single JSON log line from Nginx.

    Expected format:
    {
        "source_ip": "1.2.3.4",
        "timestamp": "2026-04-25T21:17:33+00:00",
        "method": "GET",
        "path": "/",
        "status": 200,
        "response_size": 6674,
        "user_agent": "curl/8.5.0",
        "request_time": 0.342
    }

    Returns parsed dict or None if invalid.
    """
    line = line.strip()
    if not line:
        return None

    try:
        entry = json.loads(line)

        # Validate required fields
        required = ["source_ip", "timestamp", "method",
                    "path", "status", "response_size"]
        for field in required:
            if field not in entry:
                print(f"[MONITOR] Missing field: {field}")
                return None

        return entry

    except json.JSONDecodeError as e:
        print(f"[MONITOR] Failed to parse line: {e}")
        return None


def is_error_status(status: int) -> bool:
    """Return True if status is 4xx or 5xx."""
    return status >= 400


def process_log_entry(entry: dict) -> None:
    """
    Process a single parsed log entry.

    Steps:
    1. Record request in sliding window
    2. Record error if 4xx/5xx
    3. Check for per-IP anomaly
    4. Check for global anomaly
    5. Block IP if anomaly detected
    """
    ip = entry["source_ip"]
    status = entry["status"]

    # Record in sliding window
    record_request(ip)

    # Record error if applicable
    if is_error_status(status):
        record_error(ip)

    # Check per-IP anomaly
    result = check_ip(ip)
    if result:
        block_ip(ip, result)

    # Check global anomaly (every request)
    global_result = check_global()
    if global_result:
        send_global_anomaly_alert(global_result)


def tail_log_file() -> None:
    """
    Continuously tail the Nginx log file and process new lines.

    WHY THIS APPROACH?
    We use Python's file seek to move to the end of the file
    first, then read new lines as they are written.
    This is exactly how 'tail -f' works in Linux.

    HANDLES:
    - File not existing yet (waits until it appears)
    - Log rotation (detects file size decrease)
    """
    print(f"[MONITOR] Waiting for log file: {LOG_FILE}")

    # Wait for log file to exist
    while not os.path.exists(LOG_FILE):
        print(f"[MONITOR] Log file not found, retrying in 5s...")
        time.sleep(5)

    print(f"[MONITOR] Log file found. Starting tail...")

    with open(LOG_FILE, "r") as f:
        # Seek to end of file — ignore historical entries
        f.seek(0, 2)
        last_size = f.tell()

        while True:
            # Check if file was rotated (size decreased)
            current_size = os.path.getsize(LOG_FILE)
            if current_size < last_size:
                print("[MONITOR] Log rotation detected, resetting...")
                f.seek(0)

            last_size = current_size

            # Read new lines
            line = f.readline()

            if not line:
                # No new data — wait briefly
                time.sleep(0.1)
                continue

            # Parse and process the line
            entry = parse_log_line(line)
            if entry:
                process_log_entry(entry)


def start_monitor_thread() -> threading.Thread:
    """Start the log monitor in a background thread."""
    thread = threading.Thread(
        target=tail_log_file,
        name="log-monitor",
        daemon=True
    )
    thread.start()
    print("[MONITOR] Log monitor started")
    return thread
