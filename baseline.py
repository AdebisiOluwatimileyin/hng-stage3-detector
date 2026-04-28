# baseline.py — Rolling 30-minute traffic baseline engine
#
# CONCEPT: The baseline is the "normal" traffic level.
# Think of it like knowing a shop is usually busy at lunchtime.
# If suddenly 10x more people show up at 3am, that's suspicious.
#
# HOW IT WORKS:
# - We keep a 30-minute rolling history of request rates
# - Every 60 seconds we recalculate the mean and standard deviation
# - We use per-hour buckets so we compare like-for-like
# - (Rush hour traffic compared to rush hour, not midnight)

import time
import math
import threading
from datetime import datetime
from collections import defaultdict

import state
from config import (
    BASELINE_WINDOW_MINUTES,
    BASELINE_RECALC_INTERVAL
)


def get_current_hour() -> int:
    """Return the current hour (0-23)."""
    return datetime.utcnow().hour


def record_rate(rate: float) -> None:
    """
    Record the current global request rate into the appropriate hour bucket.
    
    Example:
    At 14:35 UTC, rate = 12.5 req/sec
    baseline_buckets[14].append(12.5)
    
    We keep only the last 30 minutes of data per bucket.
    Max entries per bucket = 30 (one per minute).
    """
    hour = get_current_hour()
    
    with state.lock:
        state.baseline_buckets[hour].append(rate)
        
        # Keep only last 30 entries (30 minutes × 1 per minute)
        max_entries = BASELINE_WINDOW_MINUTES
        if len(state.baseline_buckets[hour]) > max_entries:
            state.baseline_buckets[hour] = state.baseline_buckets[hour][-max_entries:]


def calculate_mean(values: list) -> float:
    """
    Calculate the arithmetic mean of a list of values.
    
    Example: [10, 20, 30] → mean = 20.0
    """
    if not values:
        return 0.0
    return sum(values) / len(values)


def calculate_stddev(values: list, mean: float) -> float:
    """
    Calculate the standard deviation of a list of values.
    
    Standard deviation measures how spread out the values are.
    
    Example:
    values = [10, 10, 10] → stddev = 0.0 (very consistent)
    values = [1, 10, 100] → stddev = high (very inconsistent)
    
    A low stddev means traffic is predictable.
    A high stddev means traffic varies a lot.
    """
    if len(values) < 2:
        return 0.0
    
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def recalculate_baseline() -> None:
    """
    Recalculate mean and standard deviation from historical data.
    
    Strategy:
    1. Prefer current hour data if we have at least 5 data points
    2. Otherwise use all available data from all hours
    
    This ensures we compare current traffic to similar-time traffic.
    For example, 3am traffic is compared to previous 3am data,
    not to noon rush hour data.
    """
    hour = get_current_hour()
    
    with state.lock:
        current_hour_data = state.baseline_buckets.get(hour, [])
        
        # Prefer current hour if we have enough data points
        if len(current_hour_data) >= 5:
            data = current_hour_data
        else:
            # Fall back to all available data
            data = []
            for bucket_data in state.baseline_buckets.values():
                data.extend(bucket_data)
        
        if not data:
            # Not enough data yet — use safe defaults
            state.baseline_mean = 0.0
            state.baseline_stddev = 0.0
            return
        
        mean = calculate_mean(data)
        stddev = calculate_stddev(data, mean)
        
        state.baseline_mean = mean
        state.baseline_stddev = stddev


def baseline_worker() -> None:
    """
    Background thread that recalculates baseline every 60 seconds.
    
    This runs forever in the background, quietly updating
    the baseline mean and stddev that the detector uses.
    """
    print("[BASELINE] Baseline engine started")
    
    while True:
        time.sleep(BASELINE_RECALC_INTERVAL)
        
        # Record current rate into baseline history
        from sliding_window import get_global_rate
        current_rate = get_global_rate()
        record_rate(current_rate)
        
        # Recalculate stats
        recalculate_baseline()
        
        with state.lock:
            mean = state.baseline_mean
            stddev = state.baseline_stddev
        
        print(f"[BASELINE] mean={mean:.3f} req/s | stddev={stddev:.3f}")


def start_baseline_thread() -> threading.Thread:
    """Start the baseline engine in a background thread."""
    thread = threading.Thread(
        target=baseline_worker,
        name="baseline-engine",
        daemon=True  # Dies when main program exits
    )
    thread.start()
    return thread
