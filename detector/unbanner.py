# unbanner.py — Auto-unban with backoff schedule
#
# CONCEPT: The unbanner is like a parole board.
# It checks every 10 seconds if any banned IP's time is up.
# If yes, it releases them — but with increasing penalties
# for repeat offenders.
#
# BACKOFF SCHEDULE:
# First ban   → 10 minutes
# Second ban  → 30 minutes
# Third ban   → 2 hours
# Fourth ban+ → permanent
#
# WHY BACKOFF?
# If an attacker keeps coming back, each ban gets longer.
# Eventually they are permanently blocked.
# This is the same strategy used by fail2ban and CloudFlare.

import time
import threading

import state
from config import UNBAN_SCHEDULE, BLOCK_CHECK_INTERVAL
from blocker import block_ip, unblock_ip
from audit import log_action


def get_next_ban_duration(current_level: int) -> int:
    """
    Get the duration for the next ban level.
    
    Example:
    current_level = 0 (just unbanned from first ban)
    next ban = UNBAN_SCHEDULE[1] = 1800 seconds (30 minutes)
    
    If at max level, return -1 (permanent).
    """
    next_level = current_level + 1
    if next_level >= len(UNBAN_SCHEDULE):
        return -1  # Permanent
    return UNBAN_SCHEDULE[next_level]


def check_unbans() -> None:
    """
    Check all banned IPs and unban those whose time has expired.
    
    For each banned IP:
    1. Is it permanent? Skip.
    2. Has the unban time passed? Yes → unban it.
    3. Record the ban level so next ban is longer.
    """
    now = time.time()

    # Get a snapshot of banned IPs to avoid modifying dict while iterating
    with state.lock:
        banned_snapshot = dict(state.banned_ips)

    for ip, ban_info in banned_snapshot.items():
        unban_at = ban_info.get("unban_at", -1)

        # Permanent ban — never unban
        if unban_at == -1:
            continue

        # Ban time has not expired yet
        if now < unban_at:
            remaining = int(unban_at - now)
            continue

        # Ban time has expired — unban the IP
        print(f"[UNBANNER] Unbanning {ip} (level {ban_info.get('level', 0)})")
        unblock_ip(ip)


def reban_ip(ip: str, previous_level: int, detection_result: dict) -> None:
    """
    Re-ban an IP at the next backoff level if it reoffends.
    
    Called by the detector when a previously banned IP
    is detected attacking again after being unbanned.
    """
    next_level = min(previous_level + 1, len(UNBAN_SCHEDULE) - 1)
    duration = UNBAN_SCHEDULE[next_level]
    now = time.time()
    unban_at = now + duration if duration != -1 else -1

    with state.lock:
        state.banned_ips[ip] = {
            "banned_at": now,
            "level": next_level,
            "unban_at": unban_at,
            "condition": detection_result.get("condition", "reoffense"),
            "rate": detection_result.get("rate", 0),
            "baseline": detection_result.get("baseline_mean", 0)
        }

    duration_str = f"{duration}s" if duration != -1 else "permanent"

    log_action(
        "REBAN",
        ip=ip,
        condition=f"reoffense | level={next_level}",
        rate=detection_result.get("rate", 0),
        baseline=detection_result.get("baseline_mean", 0),
        duration=duration_str
    )

    print(f"[UNBANNER] Rebanned {ip} at level {next_level} for {duration_str}")


def unbanner_worker() -> None:
    """
    Background thread that checks for expired bans every 10 seconds.
    Runs forever in the background.
    """
    print("[UNBANNER] Auto-unban engine started")

    while True:
        time.sleep(BLOCK_CHECK_INTERVAL)
        check_unbans()


def start_unbanner_thread() -> threading.Thread:
    """Start the unbanner in a background thread."""
    thread = threading.Thread(
        target=unbanner_worker,
        name="unbanner-engine",
        daemon=True
    )
    thread.start()
    return thread
