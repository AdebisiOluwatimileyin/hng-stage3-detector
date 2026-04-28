# blocker.py — IP blocking using iptables
#
# CONCEPT: iptables is Linux's built-in firewall.
# Think of it like a bouncer with a blacklist.
# When we add a DROP rule for an IP, that IP's packets
# are silently discarded — they can't reach our server.
#
# HOW IT WORKS:
# 1. Anomaly detected for IP 1.2.3.4
# 2. We run: iptables -I INPUT -s 1.2.3.4 -j DROP
# 3. All packets from 1.2.3.4 are dropped
# 4. We record the ban in state.banned_ips
# 5. The unbanner will remove the rule later

import subprocess
import time
from datetime import datetime

import state
from config import UNBAN_SCHEDULE
from audit import log_action
from notifier import send_ban_alert, send_unban_alert


def run_iptables(args: list) -> bool:
    """
    Run an iptables command safely.
    
    Returns True if successful, False if failed.
    """
    try:
        result = subprocess.run(
            ["sudo", "iptables"] + args,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            print(f"[BLOCKER] iptables error: {result.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print("[BLOCKER] iptables command timed out")
        return False
    except Exception as e:
        print(f"[BLOCKER] iptables exception: {e}")
        return False


def is_already_blocked(ip: str) -> bool:
    """
    Check if an IP already has a DROP rule in iptables.
    Prevents duplicate rules.
    """
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def block_ip(ip: str, detection_result: dict) -> bool:
    """
    Block an IP address using iptables DROP rule.
    
    Steps:
    1. Check if already blocked
    2. Add iptables rule
    3. Record in state.banned_ips
    4. Send Slack alert
    5. Write audit log
    
    Ban levels (from UNBAN_SCHEDULE):
    Level 0 → 10 minutes
    Level 1 → 30 minutes
    Level 2 → 2 hours
    Level 3 → permanent
    """
    # Skip if already banned
    with state.lock:
        if ip in state.banned_ips:
            return False

    # Skip if already has iptables rule
    if is_already_blocked(ip):
        print(f"[BLOCKER] {ip} already has iptables rule")
        return False

    # Add iptables DROP rule
    # -I INPUT = Insert at the top of INPUT chain (highest priority)
    # -s ip    = Source IP to match
    # -j DROP  = Action: silently drop the packet
    success = run_iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"])

    if not success:
        print(f"[BLOCKER] Failed to block {ip}")
        return False

    now = time.time()

    # Get ban duration from schedule (level 0 = first offense)
    duration = UNBAN_SCHEDULE[0]  # 10 minutes for first ban

    # Calculate unban time (-1 means permanent)
    unban_at = now + duration if duration != -1 else -1

    # Record ban in shared state
    with state.lock:
        state.banned_ips[ip] = {
            "banned_at": now,
            "level": 0,
            "unban_at": unban_at,
            "condition": detection_result.get("condition", "unknown"),
            "rate": detection_result.get("rate", 0),
            "baseline": detection_result.get("baseline_mean", 0)
        }
        state.total_blocked += 1

    # Write audit log
    log_action(
        "BAN",
        ip=ip,
        condition=detection_result.get("condition", "unknown"),
        rate=detection_result.get("rate", 0),
        baseline=detection_result.get("baseline_mean", 0),
        duration=duration if duration != -1 else "permanent"
    )

    # Send Slack alert
    send_ban_alert(ip, detection_result, duration)

    print(f"[BLOCKER] Banned {ip} for {duration}s | {detection_result.get('condition')}")
    return True


def unblock_ip(ip: str) -> bool:
    """
    Remove the iptables DROP rule for an IP.
    Called by the unbanner when ban expires.
    """
    # Remove iptables rule
    # -D INPUT = Delete from INPUT chain
    success = run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])

    if not success:
        print(f"[BLOCKER] Failed to unblock {ip}")
        return False

    # Get ban info before removing
    with state.lock:
        ban_info = state.banned_ips.get(ip, {})

    # Remove from banned state
    with state.lock:
        if ip in state.banned_ips:
            del state.banned_ips[ip]

    # Write audit log
    log_action(
        "UNBAN",
        ip=ip,
        condition=ban_info.get("condition", "unknown"),
        rate=ban_info.get("rate", 0),
        baseline=ban_info.get("baseline", 0)
    )

    # Send Slack alert
    send_unban_alert(ip, ban_info)

    print(f"[BLOCKER] Unbanned {ip}")
    return True
