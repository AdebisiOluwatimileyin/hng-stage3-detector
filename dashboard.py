# dashboard.py — Live web dashboard using Flask
#
# CONCEPT: The dashboard is like a CCTV control room.
# It shows everything happening in real time:
# - Banned IPs
# - Current request rate
# - Top 10 IPs
# - CPU/memory usage
# - Baseline stats
# - System uptime
#
# Auto-refreshes every 3 seconds.

import time
import threading
import psutil
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string

import state
from config import DASHBOARD_PORT, DASHBOARD_REFRESH_SECONDS
from sliding_window import get_top_ips, get_global_rate

app = Flask(__name__)

# ─── HTML Template ────────────────────────────────────────────────
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="{{ refresh }}">
    <title>HNG Anomaly Detector — Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff41;
            padding: 20px;
        }
        h1 {
            color: #00ff41;
            border-bottom: 1px solid #00ff41;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.4em;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: #111;
            border: 1px solid #00ff41;
            border-radius: 4px;
            padding: 15px;
        }
        .card h2 {
            color: #00ff41;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            border-bottom: 1px solid #333;
            padding-bottom: 5px;
        }
        .stat {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            font-size: 0.85em;
            border-bottom: 1px solid #1a1a1a;
        }
        .stat-value { color: #fff; }
        .danger { color: #ff4444; }
        .warning { color: #ffaa00; }
        .ok { color: #00ff41; }
        .banned-ip {
            background: #1a0000;
            border: 1px solid #ff4444;
            border-radius: 3px;
            padding: 8px;
            margin: 5px 0;
            font-size: 0.8em;
        }
        .banned-ip .ip { color: #ff4444; font-weight: bold; }
        .banned-ip .detail { color: #888; margin-top: 3px; }
        .top-ip {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            font-size: 0.8em;
            border-bottom: 1px solid #1a1a1a;
        }
        .top-ip .count { color: #ffaa00; }
        .uptime { color: #00aaff; }
        .footer {
            text-align: center;
            color: #444;
            font-size: 0.75em;
            margin-top: 20px;
        }
        .pulse {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #00ff41;
            border-radius: 50%;
            animation: pulse 1s infinite;
            margin-right: 8px;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.3; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <h1>
        <span class="pulse"></span>
        HNG Anomaly Detection System — Live Dashboard
    </h1>

    <div class="grid">

        <!-- System Stats -->
        <div class="card">
            <h2>⚡ System Stats</h2>
            <div class="stat">
                <span>Uptime</span>
                <span class="stat-value uptime">{{ stats.uptime }}</span>
            </div>
            <div class="stat">
                <span>CPU Usage</span>
                <span class="stat-value {% if stats.cpu > 80 %}danger{% elif stats.cpu > 60 %}warning{% else %}ok{% endif %}">
                    {{ stats.cpu }}%
                </span>
            </div>
            <div class="stat">
                <span>Memory Usage</span>
                <span class="stat-value {% if stats.memory > 80 %}danger{% elif stats.memory > 60 %}warning{% else %}ok{% endif %}">
                    {{ stats.memory }}%
                </span>
            </div>
            <div class="stat">
                <span>Total Requests</span>
                <span class="stat-value">{{ stats.total_requests }}</span>
            </div>
            <div class="stat">
                <span>Total Blocked</span>
                <span class="stat-value danger">{{ stats.total_blocked }}</span>
            </div>
        </div>

        <!-- Traffic Stats -->
        <div class="card">
            <h2>📊 Traffic Stats</h2>
            <div class="stat">
                <span>Current Rate</span>
                <span class="stat-value">{{ stats.current_rps }} req/s</span>
            </div>
            <div class="stat">
                <span>Baseline Mean</span>
                <span class="stat-value">{{ stats.baseline_mean }} req/s</span>
            </div>
            <div class="stat">
                <span>Baseline StdDev</span>
                <span class="stat-value">{{ stats.baseline_stddev }}</span>
            </div>
            <div class="stat">
                <span>Active Bans</span>
                <span class="stat-value {% if stats.active_bans > 0 %}danger{% else %}ok{% endif %}">
                    {{ stats.active_bans }}
                </span>
            </div>
            <div class="stat">
                <span>Last Updated</span>
                <span class="stat-value">{{ stats.timestamp }}</span>
            </div>
        </div>

        <!-- Top 10 IPs -->
        <div class="card">
            <h2>🔝 Top 10 IPs</h2>
            {% for ip, count in stats.top_ips %}
            <div class="top-ip">
                <span>{{ ip }}</span>
                <span class="count">{{ count }} reqs</span>
            </div>
            {% else %}
            <div style="color: #444; font-size: 0.8em;">No traffic yet</div>
            {% endfor %}
        </div>

    </div>

    <!-- Banned IPs -->
    <div class="card">
        <h2>🚫 Banned IPs ({{ stats.active_bans }} active)</h2>
        {% if stats.banned_ips %}
            {% for ip, info in stats.banned_ips.items() %}
            <div class="banned-ip">
                <div class="ip">{{ ip }}</div>
                <div class="detail">
                    Level: {{ info.level }} |
                    Condition: {{ info.condition }} |
                    Rate: {{ "%.2f"|format(info.rate) }} req/s |
                    {% if info.unban_at == -1 %}
                        <span class="danger">PERMANENT</span>
                    {% else %}
                        Unban in: {{ info.unban_in }}s
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        {% else %}
            <div style="color: #444; font-size: 0.8em; padding: 10px 0;">
                No IPs currently banned ✓
            </div>
        {% endif %}
    </div>

    <div class="footer">
        Auto-refreshing every {{ refresh }} seconds |
        HNG Anomaly Detection System |
        {{ stats.timestamp }}
    </div>
</body>
</html>
"""


def get_uptime() -> str:
    """Calculate and format system uptime."""
    if state.start_time is None:
        return "starting..."

    elapsed = time.time() - state.start_time
    td = timedelta(seconds=int(elapsed))
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    if td.days > 0:
        return f"{td.days}d {hours}h {minutes}m {seconds}s"
    elif hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    else:
        return f"{minutes}m {seconds}s"


def get_dashboard_stats() -> dict:
    """Gather all stats for the dashboard."""
    now = time.time()

    with state.lock:
        banned_ips_raw = dict(state.banned_ips)
        baseline_mean = state.baseline_mean
        baseline_stddev = state.baseline_stddev
        total_requests = state.total_requests
        total_blocked = state.total_blocked
        current_rps = state.current_rps

    # Format banned IPs with unban countdown
    banned_ips_formatted = {}
    for ip, info in banned_ips_raw.items():
        unban_at = info.get("unban_at", -1)
        unban_in = int(unban_at - now) if unban_at != -1 else -1
        banned_ips_formatted[ip] = {
            "level": info.get("level", 0),
            "condition": info.get("condition", "unknown"),
            "rate": info.get("rate", 0),
            "unban_at": unban_at,
            "unban_in": max(0, unban_in) if unban_in != -1 else -1
        }

    return {
        "uptime": get_uptime(),
        "cpu": psutil.cpu_percent(interval=None),
        "memory": psutil.virtual_memory().percent,
        "current_rps": round(get_global_rate(), 3),
        "baseline_mean": round(baseline_mean, 3),
        "baseline_stddev": round(baseline_stddev, 3),
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "active_bans": len(banned_ips_raw),
        "banned_ips": banned_ips_formatted,
        "top_ips": get_top_ips(10),
        "timestamp": datetime.utcnow().strftime("%H:%M:%S UTC")
    }


@app.route("/")
def index():
    """Main dashboard page."""
    stats = get_dashboard_stats()
    return render_template_string(
        HTML_TEMPLATE,
        stats=stats,
        refresh=DASHBOARD_REFRESH_SECONDS
    )


@app.route("/api/stats")
def api_stats():
    """JSON API endpoint for stats."""
    stats = get_dashboard_stats()
    # Convert top_ips tuples to dicts for JSON
    stats["top_ips"] = [
        {"ip": ip, "count": count}
        for ip, count in stats["top_ips"]
    ]
    return jsonify(stats)


@app.route("/api/banned")
def api_banned():
    """JSON API endpoint for banned IPs."""
    with state.lock:
        banned = dict(state.banned_ips)
    return jsonify(banned)


def start_dashboard_thread() -> threading.Thread:
    """Start the Flask dashboard in a background thread."""
    thread = threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0",
            port=DASHBOARD_PORT,
            debug=False,
            use_reloader=False
        ),
        name="dashboard",
        daemon=True
    )
    thread.start()
    print(f"[DASHBOARD] Started on http://0.0.0.0:{DASHBOARD_PORT}")
    return thread
