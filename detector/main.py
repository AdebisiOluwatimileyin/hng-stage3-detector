# main.py — Orchestrates all modules together
#
# This is the entry point of the entire system.
# It starts all background threads and keeps running.

import time
import signal
import sys

import state
from monitor import start_monitor_thread
from baseline import start_baseline_thread
from unbanner import start_unbanner_thread
from dashboard import start_dashboard_thread
from audit import log_action
from config import DASHBOARD_PORT


def handle_shutdown(signum, frame):
    """
    Gracefully handle Ctrl+C or kill signal.
    """
    print("\n[MAIN] Shutdown signal received")
    log_action("SHUTDOWN", condition="manual")
    sys.exit(0)


def main():
    """
    Start all system components and keep running.
    """
    print("=" * 60)
    print("  HNG Anomaly Detection & DDoS Protection System")
    print("=" * 60)

    # Record start time for uptime calculation
    state.start_time = time.time()

    # Register shutdown handler
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Log startup
    log_action("STARTUP", condition="system starting")

    # Start all background threads
    print("\n[MAIN] Starting all components...")

    # 1. Start log monitor (reads Nginx logs)
    monitor_thread = start_monitor_thread()

    # 2. Start baseline engine (calculates normal traffic)
    baseline_thread = start_baseline_thread()

    # 3. Start auto-unbanner (releases banned IPs)
    unbanner_thread = start_unbanner_thread()

    # 4. Start live dashboard (web UI)
    dashboard_thread = start_dashboard_thread()

    print("\n[MAIN] All components started successfully")
    print(f"[MAIN] Dashboard available at: http://0.0.0.0:{DASHBOARD_PORT}")
    print("[MAIN] Press Ctrl+C to stop\n")

    # Keep main thread alive
    while True:
        time.sleep(1)

        # Print heartbeat every 60 seconds
        elapsed = int(time.time() - state.start_time)
        if elapsed % 60 == 0 and elapsed > 0:
            with state.lock:
                banned_count = len(state.banned_ips)
                total_reqs = state.total_requests
                rps = state.current_rps
                mean = state.baseline_mean

            print(
                f"[HEARTBEAT] uptime={elapsed}s | "
                f"rps={rps:.2f} | "
                f"mean={mean:.2f} | "
                f"banned={banned_count} | "
                f"total_reqs={total_reqs}"
            )


if __name__ == "__main__":
    main()
