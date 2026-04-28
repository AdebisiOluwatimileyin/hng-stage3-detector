# notifier.py — Slack webhook alerts
#
# CONCEPT: The notifier is like a radio that alerts
# the security team whenever something important happens.
#
# ALERTS SENT:
# 1. BAN    — when an IP is blocked
# 2. UNBAN  — when an IP is released
# 3. GLOBAL — when global traffic is anomalous

import requests
import time
from datetime import datetime

from config import SLACK_WEBHOOK_URL, SLACK_ENABLED


def send_slack_message(message: dict) -> bool:
    """
    Send a message to Slack via webhook.
    
    Returns True if successful, False if failed.
    """
    if not SLACK_ENABLED:
        print(f"[NOTIFIER] Slack disabled. Would have sent: {message.get('text', '')[:50]}")
        return False

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            json=message,
            timeout=10
        )
        if response.status_code == 200:
            return True
        else:
            print(f"[NOTIFIER] Slack error: {response.status_code} {response.text}")
            return False
    except requests.RequestException as e:
        print(f"[NOTIFIER] Slack request failed: {e}")
        return False


def format_timestamp() -> str:
    """Return current UTC timestamp as readable string."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def send_ban_alert(ip: str, detection_result: dict, duration) -> None:
    """
    Send a Slack alert when an IP is banned.
    
    Example message:
    🚨 IP BANNED
    IP: 1.2.3.4
    Condition: zscore=4.2 | rate=45.2>40.5
    Rate: 45.20 req/s
    Baseline: 8.10 req/s
    Duration: 600s
    Time: 2026-04-25 21:17:33 UTC
    """
    duration_str = f"{duration}s" if duration != -1 else "PERMANENT"

    message = {
        "text": "🚨 *IP BANNED*",
        "attachments": [
            {
                "color": "#ff0000",
                "fields": [
                    {
                        "title": "IP Address",
                        "value": ip,
                        "short": True
                    },
                    {
                        "title": "Duration",
                        "value": duration_str,
                        "short": True
                    },
                    {
                        "title": "Condition",
                        "value": detection_result.get("condition", "unknown"),
                        "short": False
                    },
                    {
                        "title": "Request Rate",
                        "value": f"{detection_result.get('rate', 0):.2f} req/s",
                        "short": True
                    },
                    {
                        "title": "Baseline",
                        "value": f"{detection_result.get('baseline_mean', 0):.2f} req/s",
                        "short": True
                    },
                    {
                        "title": "Timestamp",
                        "value": format_timestamp(),
                        "short": False
                    }
                ]
            }
        ]
    }

    send_slack_message(message)
    print(f"[NOTIFIER] Ban alert sent for {ip}")


def send_unban_alert(ip: str, ban_info: dict) -> None:
    """
    Send a Slack alert when an IP is unbanned.
    """
    message = {
        "text": "✅ *IP UNBANNED*",
        "attachments": [
            {
                "color": "#00ff00",
                "fields": [
                    {
                        "title": "IP Address",
                        "value": ip,
                        "short": True
                    },
                    {
                        "title": "Original Condition",
                        "value": ban_info.get("condition", "unknown"),
                        "short": False
                    },
                    {
                        "title": "Timestamp",
                        "value": format_timestamp(),
                        "short": False
                    }
                ]
            }
        ]
    }

    send_slack_message(message)
    print(f"[NOTIFIER] Unban alert sent for {ip}")


def send_global_anomaly_alert(detection_result: dict) -> None:
    """
    Send a Slack alert when global traffic is anomalous.
    """
    message = {
        "text": "⚠️ *GLOBAL TRAFFIC ANOMALY DETECTED*",
        "attachments": [
            {
                "color": "#ff9900",
                "fields": [
                    {
                        "title": "Condition",
                        "value": detection_result.get("condition", "unknown"),
                        "short": False
                    },
                    {
                        "title": "Global Rate",
                        "value": f"{detection_result.get('rate', 0):.2f} req/s",
                        "short": True
                    },
                    {
                        "title": "Baseline",
                        "value": f"{detection_result.get('baseline_mean', 0):.2f} req/s",
                        "short": True
                    },
                    {
                        "title": "Z-Score",
                        "value": f"{detection_result.get('zscore', 0):.2f}",
                        "short": True
                    },
                    {
                        "title": "Timestamp",
                        "value": format_timestamp(),
                        "short": False
                    }
                ]
            }
        ]
    }

    send_slack_message(message)
    print("[NOTIFIER] Global anomaly alert sent")
