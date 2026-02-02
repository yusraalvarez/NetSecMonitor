# Quick Start Guide - NetSecMonitor

Get up and running with NetSecMonitor in 5 minutes!

## Prerequisites

- macOS (10.14 or later)
- Python 3.8 or higher
- Terminal access

## Installation

### 1. Check Python Version
```bash
python3 --version
```
You should see Python 3.8 or higher. If not, install it from https://www.python.org/downloads/

### 2. Create Virtual Environment (Recommended)
```bash
cd NetSecMonitor
python3 -m venv venv
source venv/bin/activate
```

You'll see `(venv)` appear in your terminal prompt.

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

This will install Flask, Pandas, Plotly, and other required packages.

### 4. Initialize Database
```bash
python init_db.py
```

You should see:
```
✅ Database created successfully
📊 Created X tables
```

## Running the Project

### Start Network Monitoring (Terminal 1)
```bash
python monitor.py
```

This will start capturing network traffic (simulated for safety). You'll see:
```
🚀 Starting network monitoring...
📊 Monitoring Status
📦 Total packets captured: X
```

Leave this running in the background.

### Start Web Dashboard (Terminal 2)
Open a NEW terminal window, navigate to the project, and run:
```bash
cd NetSecMonitor
source venv/bin/activate  # Activate virtual environment
python dashboard.py
```

You'll see:
```
🚀 Starting web server...
📊 Dashboard will be available at: http://localhost:5000
```

### View Dashboard
Open your web browser and go to:
```
http://localhost:5000
```

You should see the NetSecMonitor dashboard with live statistics and charts!

## Other Commands

### Run Port Scanner
```bash
# Scan localhost
python port_scanner.py --target 127.0.0.1 --ports 1-1024

# Scan specific ports
python port_scanner.py --target 127.0.0.1 --ports 80,443,8080
```

### Run Anomaly Detection
```bash
python anomaly_detector.py
```

### Generate Security Report
```bash
# Last 24 hours
python generate_report.py --last 24h

# Last 7 days
python generate_report.py --last 7d
```

## Stopping the Services

### Stop Monitor
In the terminal running `monitor.py`, press `Ctrl+C`

### Stop Dashboard
In the terminal running `dashboard.py`, press `Ctrl+C`

### Deactivate Virtual Environment
```bash
deactivate
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'flask'"
Make sure you activated the virtual environment:
```bash
source venv/bin/activate
```
Then install dependencies:
```bash
pip install -r requirements.txt
```

### "Database not found"
Run the initialization script:
```bash
python init_db.py
```

### Port 5000 already in use
Another application is using port 5000. Edit `dashboard.py` and change:
```python
app.run(host='0.0.0.0', port=5000, debug=True)
```
to:
```python
app.run(host='0.0.0.0', port=5001, debug=True)
```
Then access dashboard at http://localhost:5001

### Permission denied for packet capture
The monitoring script uses simulated data by default, so no special permissions needed. If you later implement real packet capture with scapy, you'll need sudo:
```bash
sudo python monitor.py
```

## What to Demo in Interviews

When showing this project to interviewers:

### 1. Show the Dashboard (30 seconds)
- Open http://localhost:5000
- Point out real-time statistics
- Explain the protocol distribution chart
- Show the alerts section

### 2. Explain the Architecture (1 minute)
- "I built a network monitoring tool using Python"
- "It captures traffic, stores in SQLite database, detects anomalies"
- "Flask powers the web dashboard with Plotly for visualization"
- "Demonstrates my skills in networking, security, data engineering"

### 3. Walk Through Code (2 minutes)
- Show `monitor.py` - "This is the core monitoring logic"
- Show `database/schema.sql` - "Designed an optimized database schema"
- Show `anomaly_detector.py` - "Implemented statistical anomaly detection"
- Show `dashboard.py` - "Built RESTful API endpoints for the frontend"

### 4. Discuss Extensions
- "Could integrate with Elasticsearch/Kibana"
- "Could add machine learning for better anomaly detection"
- "Could support multiple network interfaces"
- "Could export to SIEM tools like Splunk"

## Next Steps

1. ✅ Run the project locally
2. ✅ Customize it (add features, change UI)
3. ✅ Take screenshots for your README
4. ✅ Upload to GitHub (see GITHUB_SETUP.md)
5. ✅ Add to your resume and portfolio

---

**Questions?** Check the main README.md or create an issue on GitHub.
