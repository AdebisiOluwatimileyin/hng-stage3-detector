# detector.py — Anomaly detection logic
#
# CONCEPT: The detector is like a smoke alarm.
# It continuously checks if current traffic is abnormal
# compared to the established baseline.
#
# TWO DETECTION METHODS:
#
# 1. Z-SCORE METHOD:
#    How many standard deviations above the mean is the current rate?
#    z = (current_rate - mean) / stddev
#    If z > 3.0 → anomaly (statistically very unusual)
#
#    Example:
#    mean = 10 req/s, stddev = 2, current = 17
#    z = (17 - 10) / 2 = 3.5 → ANOMALY
#
# 2. RATE MULTIPLIER METHOD:
#    Is the current rate more than 5x the baseline mean?
#    If current > mean * 5 → anomaly
#
#    This catches cases where stddev is 0 (very stable traffic)
#    and z-score would be infinite or undefined.

import time
import state
from config import (
    ZSCORE_THRESHOLD,
    RATE_MULTIPLIER,
    ERROR_RATE_MULTIPLIER
)
from sliding_window import (
    get_ip_rate,
    get_global_rate,
    get_ip_error_rate
)
from audit import log_action


def calculate_zscore(current_rate: float, mean: float, stddev: float) -> float:
    """
    Calculate the z-score of the current rate.
    
    Z-score tells us how unusual a value is:
    - z = 0   → exactly average
    - z = 1   → 1 standard deviation above average (normal)
    - z = 2   → 2 standard deviations above average (unusual)
    - z = 3+  → very unusual → ANOMALY
    
    If stddev is 0 (traffic is perfectly consistent),
    we return 0 to avoid division by zero.
    """
    if stddev == 0:
        return 0.0
    return (current_rate - mean) / stddev


def is_error_surge(ip: str, baseline_mean: float) -> bool:
    """
    Check if an IP has an unusually high error rate.
    
    If error rate > 3x baseline mean → tighten thresholds.
    This catches attackers who are probing for vulnerabilities
    and generating lots of 4xx/5xx errors.
    """
    error_rate = get_ip_error_rate(ip)
    threshold = baseline_mean * ERROR_RATE_MULTIPLIER
    
    return error_rate > threshold and error_rate > 0


def get_dynamic_thresholds(ip: str, baseline_mean: float) -> tuple:
    """
    Return detection thresholds, tightened if error surge detected.
    
    Normal thresholds:
    - z-score > 3.0
    - rate > 5x baseline
    
    Tightened thresholds (error surge):
    - z-score > 2.0
    - rate > 3x baseline
    """
    if is_error_surge(ip, baseline_mean):
        return 2.0, 3.0  # Tightened
    return ZSCORE_THRESHOLD, RATE_MULTIPLIER  # Normal


def check_ip(ip: str) -> dict | None:
    """
    Check if a specific IP is behaving anomalously.
    
    Returns a detection result dict if anomaly found, None otherwise.
    
    Result format:
    {
        "ip": "1.2.3.4",
        "rate": 45.2,
        "baseline_mean": 8.1,
        "baseline_stddev": 1.2,
        "zscore": 30.9,
        "condition": "zscore",
        "error_surge": False
    }
    """
    with state.lock:
        mean = state.baseline_mean
        stddev = state.baseline_stddev
    
    # Not enough baseline data yet — skip detection
    if mean == 0.0:
        return None
    
    # Skip already banned IPs
    with state.lock:
        if ip in state.banned_ips:
            return None
    
    current_rate = get_ip_rate(ip)
    
    # No requests from this IP — skip
    if current_rate == 0:
        return None
    
    # Get dynamic thresholds (may be tightened due to error surge)
    zscore_threshold, rate_threshold = get_dynamic_thresholds(ip, mean)
    error_surge = is_error_surge(ip, mean)
    
    # Calculate z-score
    zscore = calculate_zscore(current_rate, mean, stddev)
    
    # Check both detection conditions
    zscore_triggered = zscore > zscore_threshold
    rate_triggered = current_rate > (mean * rate_threshold)
    
    if zscore_triggered or rate_triggered:
        condition = []
        if zscore_triggered:
            condition.append(f"zscore={zscore:.2f}")
        if rate_triggered:
            condition.append(f"rate={current_rate:.2f}>{mean * rate_threshold:.2f}")
        if error_surge:
            condition.append("error_surge")
        
        condition_str = " | ".join(condition)
        
        log_action(
            "ANOMALY_DETECTED",
            ip=ip,
            condition=condition_str,
            rate=current_rate,
            baseline=mean
        )
        
        return {
            "ip": ip,
            "rate": current_rate,
            "baseline_mean": mean,
            "baseline_stddev": stddev,
            "zscore": zscore,
            "condition": condition_str,
            "error_surge": error_surge
        }
    
    return None


def check_global() -> dict | None:
    """
    Check if global traffic (all IPs combined) is anomalous.
    
    This catches distributed attacks where many IPs each
    send a moderate number of requests — no single IP
    triggers the per-IP detector, but the total is huge.
    """
    with state.lock:
        mean = state.baseline_mean
        stddev = state.baseline_stddev
    
    if mean == 0.0:
        return None
    
    current_rate = get_global_rate()
    
    if current_rate == 0:
        return None
    
    zscore = calculate_zscore(current_rate, mean, stddev)
    
    zscore_triggered = zscore > ZSCORE_THRESHOLD
    rate_triggered = current_rate > (mean * RATE_MULTIPLIER)
    
    if zscore_triggered or rate_triggered:
        condition = []
        if zscore_triggered:
            condition.append(f"global_zscore={zscore:.2f}")
        if rate_triggered:
            condition.append(f"global_rate={current_rate:.2f}")
        
        condition_str = " | ".join(condition)
        
        log_action(
            "GLOBAL_ANOMALY",
            condition=condition_str,
            rate=current_rate,
            baseline=mean
        )
        
        return {
            "type": "global",
            "rate": current_rate,
            "baseline_mean": mean,
            "baseline_stddev": stddev,
            "zscore": zscore,
            "condition": condition_str
        }
    
    return None
