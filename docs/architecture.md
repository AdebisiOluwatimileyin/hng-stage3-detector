markdown# HNG Anomaly Detection System — Architecture

## System Flow

```
Internet Traffic
      │
      ▼
┌─────────────┐
│    Nginx    │ ──── JSON logs ────▶ /var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log
│ (Port 80)   │
└─────────────┘
      │
      ▼
┌─────────────┐
│  Nextcloud  │
│  (Docker)   │
└─────────────┘

Log File
      │
      ▼
┌─────────────┐
│  monitor.py │ ──── Parses JSON log lines in real time
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ sliding_window  │ ──── deque per IP + global deque (60s window)
└──────┬──────────┘
       │
       ├──────────────────┐
       ▼                  ▼
┌─────────────┐    ┌─────────────┐
│ baseline.py │    │ detector.py │
│ 30min history│   │ z-score > 3 │
│ mean/stddev │    │ rate > 5x   │
└─────────────┘    └──────┬──────┘
                          │
                          ▼
                   ┌─────────────┐
                   │  blocker.py │ ──── iptables DROP rule
                   └──────┬──────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
       ┌─────────────┐        ┌─────────────┐
       │ unbanner.py │        │ notifier.py │
       │ backoff     │        │ Slack alerts│
       │ schedule    │        └─────────────┘
       └─────────────┘

                   ┌─────────────┐
                   │dashboard.py │ ──── http://server:5000
                   │ Flask UI    │      Auto-refresh 3s
                   └─────────────┘
```
