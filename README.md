markdown# HNG Stage 3 — Anomaly Detection & DDoS Protection System

A production-grade anomaly detection daemon built for the HNG Internship Stage 3 DevSecOps challenge.

## Overview

This system monitors Nginx access logs in real time, detects anomalous traffic patterns using statistical analysis, automatically blocks malicious IPs using iptables, and provides a live web dashboard.

## Architecture
Nginx (JSON logs) → monitor.py → sliding_window → detector.py → blocker.py
→ notifier.py (Slack)
baseline.py ──────────▶ detector.py
unbanner.py (auto-unban with backoff)
dashboard.py (Flask live UI)

## Features

- **Real-time log monitoring** — tails Nginx JSON logs continuously
- **Sliding window tracking** — per-IP and global request tracking using deque
- **Statistical baseline** — 30-minute rolling mean and standard deviation
- **Anomaly detection** — z-score > 3.0 OR rate > 5x baseline
- **Error surge detection** — tightens thresholds when error rate spikes
- **Auto-blocking** — iptables DROP rule within 10 seconds of detection
- **Auto-unban** — backoff schedule: 10min → 30min → 2hr → permanent
- **Slack alerts** — ban, unban, and global anomaly notifications
- **Live dashboard** — Flask web UI auto-refreshing every 3 seconds

## Project Structure
detector/
main.py           # Entry point
monitor.py        # Nginx log tailer and parser
baseline.py       # Rolling 30-min baseline engine
detector.py       # Anomaly detection logic
blocker.py        # iptables blocking
unbanner.py       # Auto-unban with backoff
notifier.py       # Slack webhook alerts
dashboard.py      # Flask live dashboard
sliding_window.py # deque-based request tracking
state.py          # Shared state between modules
audit.py          # Structured audit logging
config.py         # Configuration
config.yaml       # Configuration (YAML format)
requirements.txt  # Python dependencies
nginx/
nginx.conf        # Nginx reverse proxy with JSON logging
docs/
architecture.md   # System architecture
screenshots/        # Dashboard screenshots
README.md           # This file

## Prerequisites

- Ubuntu 24.04
- Docker and Docker Compose
- Python 3.10+
- iptables

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/AdebisiOluwatimileyin/hng-stage3-detector.git
cd hng-stage3-detector
```

### 2. Start Nextcloud and Nginx

```bash
cd /opt/hng-nextcloud
docker compose up -d
```

### 3. Set up Python environment

```bash
cd detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
export SLACK_WEBHOOK_URL=your_slack_webhook_url
```

### 5. Run the daemon

```bash
python3 main.py
```

### 6. Run as systemd service

```bash
sudo systemctl enable hng-detector
sudo systemctl start hng-detector
```

## Live Dashboard

Access the dashboard at: `http://YOUR_SERVER_IP:5000`

Shows:
- Banned IPs with countdown timers
- Current requests per second
- Top 10 IPs by request count
- CPU and memory usage
- Baseline mean and standard deviation
- System uptime

## Detection Logic

### Z-Score Method
z = (current_rate - baseline_mean) / baseline_stddev
if z > 3.0 → anomaly detected

### Rate Multiplier Method
if current_rate > baseline_mean * 5.0 → anomaly detected

### Error Surge Detection
if error_rate > baseline_mean * 3.0 → tighten thresholds
zscore_threshold: 3.0 → 2.0
rate_multiplier: 5.0 → 3.0

## Auto-Unban Schedule

| Offense | Duration |
|---------|----------|
| 1st ban | 10 minutes |
| 2nd ban | 30 minutes |
| 3rd ban | 2 hours |
| 4th ban | Permanent |

## Audit Log

All actions are logged to `/opt/hng-detector/logs/audit.log`:
[2026-04-28T22:43:13] STARTUP | condition=system starting
[2026-04-28T22:43:13] BAN | 1.2.3.4 | condition=zscore=4.2 | rate=45.20 | baseline=8.10 | duration=600s
[2026-04-28T22:43:13] UNBAN | 1.2.3.4 | condition=zscore=4.2 | rate=45.20 | baseline=8.10

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |

## Server Details

- **Server IP:** 3.90.230.120
- **Dashboard:** http://3.90.230.120:5000
- **Nextcloud:** http://3.90.230.120
