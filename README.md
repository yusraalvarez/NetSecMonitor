# NetSecMonitor 🔒

A comprehensive network security monitoring and analysis tool built with Python. This project demonstrates network traffic analysis, security event detection, data pipeline engineering, and real-time monitoring capabilities.

## 🎯 Purpose

NetSecMonitor is designed to monitor network activity, detect anomalies, and provide actionable security insights. Perfect for demonstrating skills in:
- **Network Engineering**: Traffic analysis, protocol monitoring, network diagnostics
- **Security Engineering**: Threat detection, anomaly identification, security logging
- **Data Engineering**: ETL pipelines, time-series data handling, SQL query optimization
- **Systems Engineering**: Automated monitoring, alerting, operational dashboards

## 🚀 Features

### 1. Network Traffic Monitor
- Real-time packet capture and analysis
- Protocol classification (TCP, UDP, ICMP, etc.)
- Traffic volume tracking by source/destination
- Bandwidth utilization metrics

### 2. Port Scanner
- Automated port scanning for common services
- Service fingerprinting
- Open port tracking and alerting
- Scan history and comparison

### 3. Anomaly Detection
- Statistical analysis of network patterns
- Baseline establishment for normal traffic
- Alert generation for unusual activity
- Machine learning-ready feature extraction

### 4. Security Event Database
- SQLite database with optimized schema
- Indexed queries for fast lookups
- Historical data retention
- Efficient time-series storage

### 5. Analytics Dashboard
- Real-time traffic visualization
- Top talkers and protocols
- Security event timeline
- Custom query interface

### 6. Alert System
- Configurable alert thresholds
- Email/log notifications
- Alert severity levels
- Event correlation

## 🛠️ Technology Stack

- **Python 3.8+**: Core application logic
- **SQLite3**: Database for event storage
- **Flask**: Web dashboard framework
- **Scapy**: Packet capture and analysis
- **Pandas**: Data analysis and aggregation
- **Plotly**: Interactive data visualization
- **APScheduler**: Automated monitoring tasks

## 📋 Prerequisites

- Python 3.8 or higher
- macOS (tested on macOS 11+)
- Administrator privileges (for packet capture)

## 🔧 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/NetSecMonitor.git
cd NetSecMonitor
```

### 2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize the database
```bash
python init_db.py
```

## 🚀 Usage

### Start the monitoring service
```bash
# Run with sudo for packet capture capabilities
sudo python monitor.py
```

### Launch the web dashboard
```bash
python dashboard.py
```
Then open your browser to `http://localhost:5000`

### Run port scanner
```bash
python port_scanner.py --target localhost --ports 1-1024
```

### Generate security report
```bash
python generate_report.py --last 24h
```

## 📊 Dashboard Features

The web dashboard provides:
- **Live Traffic View**: Real-time packet statistics
- **Protocol Distribution**: Pie chart of traffic by protocol
- **Timeline View**: Historical traffic patterns
- **Top Talkers**: Most active IP addresses
- **Alert Feed**: Recent security events
- **Custom Queries**: SQL interface for ad-hoc analysis

## 🔐 Security Considerations

**IMPORTANT**: This tool is for educational and personal network monitoring only.

- Only monitor networks you own or have explicit permission to monitor
- Packet capture requires elevated privileges - use responsibly
- Sensitive data is NOT logged (passwords, auth tokens, etc.)
- All monitoring is local to your machine
- No external data transmission

## 📁 Project Structure

```
NetSecMonitor/
├── README.md
├── requirements.txt
├── init_db.py              # Database initialization
├── monitor.py              # Main monitoring service
├── port_scanner.py         # Port scanning module
├── anomaly_detector.py     # Anomaly detection engine
├── dashboard.py            # Flask web dashboard
├── generate_report.py      # Reporting utilities
├── database/
│   └── schema.sql          # Database schema
├── static/
│   ├── css/
│   └── js/
└── templates/
    └── dashboard.html
```

## 🎓 Learning Outcomes

This project demonstrates:

### Network Engineering
- Understanding of TCP/IP stack
- Packet structure and analysis
- Network troubleshooting skills
- Protocol knowledge (HTTP, DNS, SSH, etc.)

### Security Engineering
- Security event logging
- Threat detection methodologies
- Anomaly identification
- Security operations concepts

### Data Engineering
- ETL pipeline design
- Time-series data handling
- SQL query optimization
- Data aggregation and reporting

### Systems Engineering
- Service automation
- Monitoring and alerting
- Dashboard development
- System integration

## 📈 Future Enhancements

- [ ] Integration with external SIEM tools
- [ ] Machine learning-based anomaly detection
- [ ] GeoIP mapping for traffic sources
- [ ] Export to PCAP format
- [ ] Support for multiple network interfaces
- [ ] Container deployment (Docker)
- [ ] REST API for programmatic access
- [ ] Integration with threat intelligence feeds

## 🤝 Contributing

This is a portfolio project, but suggestions and feedback are welcome! Feel free to open an issue or submit a pull request.

## 📝 License

MIT License - feel free to use this project for learning and portfolio purposes.

## 👤 Author

**Yusra Alvarez**
- Systems Engineer with expertise in infrastructure automation and security
- 2+ years experience at Meta
- Passionate about network security and data engineering

## 🙏 Acknowledgments

- Built as a demonstration of practical DevOps and security engineering skills
- Inspired by real-world network monitoring challenges
- Thanks to the open-source community for amazing tools like Scapy and Flask

---

**⚠️ Disclaimer**: This tool is for educational purposes and personal network monitoring only. Always obtain proper authorization before monitoring any network.
