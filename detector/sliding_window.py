# sliding_window.py — Tracks requests using deque (NOT counters)
#
# CONCEPT: A sliding window is like a conveyor belt.
# Old items fall off one end as new ones are added to the other.
# We only count items that happened in the last 60 seconds.
#
# WHY deque? It's a double-ended queue — fast to add to the right
# and fast to remove from the left. Perfect for this use case.

import time
from collections import deque
import state
from config import WINDOW_SECONDS, GLOBAL_WINDOW_SECONDS


def evict_old_entries(window: deque, max_age: float) -> None:
    """
    Remove entries older than max_age seconds from the LEFT of the deque.
    
    Example:
    window = deque([1000.0, 1010.0, 1055.0, 1060.0])
    current_time = 1065.0
    max_age = 60
    cutoff = 1065.0 - 60 = 1005.0
    
    → Remove 1000.0 (older than 1005.0)
    → Keep 1010.0, 1055.0, 1060.0
    """
    cutoff = time.time() - max_age
    while window and window[0] < cutoff:
        window.popleft()


def record_request(ip: str) -> None:
    """
    Record a new request for a given IP and globally.
    Called every time a new log line is parsed.
    """
    now = time.time()
    
    with state.lock:
        # Add timestamp to per-IP window
        state.ip_window[ip].append(now)
        
        # Add timestamp to global window
        state.global_window.append(now)
        
        # Track total request count per IP (for dashboard top 10)
        state.ip_request_counts[ip] += 1
        
        # Increment total requests seen
        state.total_requests += 1
        
        # Evict old entries immediately after adding
        evict_old_entries(state.ip_window[ip], WINDOW_SECONDS)
        evict_old_entries(state.global_window, GLOBAL_WINDOW_SECONDS)


def record_error(ip: str) -> None:
    """
    Record an error request (4xx or 5xx) for a given IP.
    Used for error surge detection.
    """
    now = time.time()
    
    with state.lock:
        state.ip_error_window[ip].append(now)
        evict_old_entries(state.ip_error_window[ip], WINDOW_SECONDS)


def get_ip_rate(ip: str) -> float:
    """
    Get the current request rate for a specific IP.
    Returns requests per second over the last 60 seconds.
    
    Example:
    If an IP made 120 requests in the last 60 seconds:
    rate = 120 / 60 = 2.0 requests/second
    """
    with state.lock:
        evict_old_entries(state.ip_window[ip], WINDOW_SECONDS)
        count = len(state.ip_window[ip])
    
    return count / WINDOW_SECONDS


def get_global_rate() -> float:
    """
    Get the current global request rate across all IPs.
    Returns requests per second over the last 60 seconds.
    """
    with state.lock:
        evict_old_entries(state.global_window, GLOBAL_WINDOW_SECONDS)
        count = len(state.global_window)
        
        # Update the shared current_rps stat for dashboard
        state.current_rps = count / GLOBAL_WINDOW_SECONDS
    
    return state.current_rps


def get_ip_error_rate(ip: str) -> float:
    """
    Get the error rate for a specific IP.
    Returns error requests per second over the last 60 seconds.
    """
    with state.lock:
        evict_old_entries(state.ip_error_window[ip], WINDOW_SECONDS)
        count = len(state.ip_error_window[ip])
    
    return count / WINDOW_SECONDS


def get_top_ips(n: int = 10) -> list:
    """
    Get the top N IPs by total request count.
    Returns list of (ip, count) tuples sorted by count descending.
    """
    with state.lock:
        sorted_ips = sorted(
            state.ip_request_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
    
    return sorted_ips[:n]
