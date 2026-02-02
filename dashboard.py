#!/usr/bin/env python3
"""
Web Dashboard for NetSecMonitor
Provides real-time visualization of network traffic and security alerts
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime, timedelta
import json

app = Flask(__name__)
DB_PATH = "netsec_monitor.db"

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats/overview')
def stats_overview():
    """Get overview statistics"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Total packets
    cursor.execute("SELECT COUNT(*) FROM traffic_events")
    total_packets = cursor.fetchone()[0]
    
    # Packets last hour
    cursor.execute("""
        SELECT COUNT(*) FROM traffic_events 
        WHERE timestamp > datetime('now', '-1 hour')
    """)
    packets_last_hour = cursor.fetchone()[0]
    
    # Open alerts
    cursor.execute("""
        SELECT COUNT(*) FROM security_alerts 
        WHERE status = 'open'
    """)
    open_alerts = cursor.fetchone()[0]
    
    # Unique IPs last 24h
    cursor.execute("""
        SELECT COUNT(DISTINCT source_ip) FROM traffic_events
        WHERE timestamp > datetime('now', '-24 hours')
    """)
    unique_ips = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_packets': total_packets,
        'packets_last_hour': packets_last_hour,
        'open_alerts': open_alerts,
        'unique_ips': unique_ips
    })

@app.route('/api/traffic/recent')
def traffic_recent():
    """Get recent traffic events"""
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT timestamp, source_ip, destination_ip, protocol, 
               packet_size, source_port, destination_port
        FROM traffic_events
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    
    events = []
    for row in cursor.fetchall():
        events.append({
            'timestamp': row[0],
            'source_ip': row[1],
            'destination_ip': row[2],
            'protocol': row[3],
            'packet_size': row[4],
            'source_port': row[5],
            'destination_port': row[6]
        })
    
    conn.close()
    return jsonify(events)

@app.route('/api/traffic/timeline')
def traffic_timeline():
    """Get traffic volume over time"""
    hours = request.args.get('hours', 24, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket,
            COUNT(*) as packet_count,
            SUM(packet_size) as total_bytes
        FROM traffic_events
        WHERE timestamp > datetime('now', ?)
        GROUP BY time_bucket
        ORDER BY time_bucket
    """, (f'-{hours} hours',))
    
    timeline = []
    for row in cursor.fetchall():
        timeline.append({
            'time': row[0],
            'packets': row[1],
            'bytes': row[2]
        })
    
    conn.close()
    return jsonify(timeline)

@app.route('/api/protocols/distribution')
def protocol_distribution():
    """Get protocol distribution"""
    hours = request.args.get('hours', 24, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT protocol, COUNT(*) as count
        FROM traffic_events
        WHERE timestamp > datetime('now', ?)
        GROUP BY protocol
        ORDER BY count DESC
    """, (f'-{hours} hours',))
    
    protocols = []
    for row in cursor.fetchall():
        protocols.append({
            'protocol': row[0],
            'count': row[1]
        })
    
    conn.close()
    return jsonify(protocols)

@app.route('/api/top-talkers')
def top_talkers():
    """Get most active IP addresses"""
    limit = request.args.get('limit', 10, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            source_ip,
            COUNT(*) as packet_count,
            SUM(packet_size) as total_bytes,
            MAX(timestamp) as last_seen
        FROM traffic_events
        WHERE timestamp > datetime('now', '-1 hour')
        GROUP BY source_ip
        ORDER BY packet_count DESC
        LIMIT ?
    """, (limit,))
    
    talkers = []
    for row in cursor.fetchall():
        talkers.append({
            'ip': row[0],
            'packets': row[1],
            'bytes': row[2],
            'last_seen': row[3]
        })
    
    conn.close()
    return jsonify(talkers)

@app.route('/api/alerts/recent')
def alerts_recent():
    """Get recent security alerts"""
    limit = request.args.get('limit', 50, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, timestamp, alert_type, severity, source_ip,
               destination_ip, description, details, status
        FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    
    alerts = []
    for row in cursor.fetchall():
        alerts.append({
            'id': row[0],
            'timestamp': row[1],
            'type': row[2],
            'severity': row[3],
            'source_ip': row[4],
            'destination_ip': row[5],
            'description': row[6],
            'details': row[7],
            'status': row[8]
        })
    
    conn.close()
    return jsonify(alerts)

@app.route('/api/alerts/by-severity')
def alerts_by_severity():
    """Get alert counts by severity"""
    hours = request.args.get('hours', 24, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM security_alerts
        WHERE timestamp > datetime('now', ?)
        GROUP BY severity
    """, (f'-{hours} hours',))
    
    severity_counts = {}
    for row in cursor.fetchall():
        severity_counts[row[0]] = row[1]
    
    conn.close()
    return jsonify(severity_counts)

@app.route('/api/ports/scans')
def port_scans():
    """Get recent port scan results"""
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT scan_timestamp, target_ip, port, status, 
               service, response_time
        FROM port_scans
        WHERE status = 'open'
        ORDER BY scan_timestamp DESC
        LIMIT ?
    """, (limit,))
    
    scans = []
    for row in cursor.fetchall():
        scans.append({
            'timestamp': row[0],
            'target': row[1],
            'port': row[2],
            'status': row[3],
            'service': row[4],
            'response_time': row[5]
        })
    
    conn.close()
    return jsonify(scans)

if __name__ == "__main__":
    print("=" * 60)
    print("NetSecMonitor - Web Dashboard")
    print("=" * 60)
    print("\n🚀 Starting web server...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
