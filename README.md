# NetSecMonitor

Network security monitoring tool for real-time threat detection and traffic analysis.

## Overview

NetSecMonitor captures and analyzes network traffic to identify security threats, detect anomalies, and monitor system activity. Built with Python and Flask, it provides automated scanning, statistical threat detection, and a web-based dashboard for visualization.

## Features

- Real-time network traffic monitoring and protocol analysis
- Automated port scanning with service fingerprinting
- Statistical anomaly detection and baseline profiling
- Security alert generation with severity classification
- Interactive web dashboard with live metrics
- Comprehensive reporting and data export

## Installation
```bash
git clone https://github.com/yusraalvarez/NetSecMonitor.git
cd NetSecMonitor

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python init_db.py
```

## Usage

### Start Traffic Monitor
```bash
python monitor.py
```

### Launch Web Dashboard
```bash
python dashboard.py
```
Navigate to `http://localhost:5000`

### Run Port Scanner
```bash
python port_scanner.py --target 127.0.0.1 --ports 1-1024
```

### Detect Anomalies
```bash
python anomaly_detector.py
```

### Generate Report
```bash
python generate_report.py --last 24h
```

## Architecture
```
NetSecMonitor/
├── monitor.py              # Traffic monitoring engine
├── port_scanner.py         # Port scanning module
├── anomaly_detector.py     # Threat detection algorithms
├── dashboard.py            # Flask web application
├── generate_report.py      # Report generation
├── init_db.py              # Database setup
├── database/
│   └── schema.sql          # Optimized schema
└── templates/
    └── dashboard.html      # Web interface
```

## Technical Stack

- **Python 3.8+** - Core application
- **Flask** - Web framework
- **SQLite** - Time-series database with indexed queries
- **Pandas** - Data aggregation and analysis
- **Plotly** - Interactive visualizations
- **APScheduler** - Automated task scheduling

## Database Design

Optimized schema for time-series security data:
- Traffic events table with packet-level details
- Security alerts with severity tracking
- Port scan results and service identification
- Aggregated network statistics
- Baseline profiles for anomaly detection

Indexes on timestamp, IP addresses, and protocols for efficient querying.

## License

MIT License
