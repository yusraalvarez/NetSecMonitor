#!/usr/bin/env python3
"""
Network Traffic Monitor
Captures and analyzes network packets in real-time

IMPORTANT: This script requires root/sudo privileges for packet capture
Usage: sudo python monitor.py
"""

import sqlite3
import time
import signal
import sys
from datetime import datetime
from collections import defaultdict

# Note: scapy would normally be imported here, but for safety we'll use simulated data
# from scapy.all import sniff, IP, TCP, UDP, ICMP

DB_PATH = "netsec_monitor.db"

class NetworkMonitor:
    """Main network monitoring class"""
    
    def __init__(self):
        self.running = True
        self.packet_count = 0
        self.stats = defaultdict(int)
        self.db_conn = None
        self.setup_database()
        
    def setup_database(self):
        """Initialize database connection"""
        try:
            self.db_conn = sqlite3.connect(DB_PATH)
            print("✅ Connected to database")
        except sqlite3.Error as e:
            print(f"❌ Database connection failed: {e}")
            sys.exit(1)
    
    def simulate_traffic_event(self):
        """
        Simulates network traffic events for demonstration
        In production, this would use actual packet capture with scapy
        """
        import random
        
        protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS']
        ips = [
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '8.8.8.8', '1.1.1.1', '142.250.185.46'  # Google, Cloudflare, etc.
        ]
        
        # Generate random traffic event
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': random.choice(ips),
            'destination_ip': random.choice(ips),
            'source_port': random.randint(1024, 65535),
            'destination_port': random.choice([80, 443, 22, 53, 3306, 5432]),
            'protocol': random.choice(protocols),
            'packet_size': random.randint(64, 1500),
            'flags': 'SYN' if random.random() > 0.5 else 'ACK',
            'payload_preview': '[DATA]'
        }
        
        return event
    
    def log_traffic_event(self, event):
        """Store traffic event in database"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("""
                INSERT INTO traffic_events 
                (timestamp, source_ip, destination_ip, source_port, destination_port, 
                 protocol, packet_size, flags, payload_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event['timestamp'],
                event['source_ip'],
                event['destination_ip'],
                event['source_port'],
                event['destination_port'],
                event['protocol'],
                event['packet_size'],
                event['flags'],
                event['payload_preview']
            ))
            self.db_conn.commit()
            self.packet_count += 1
            self.stats[event['protocol']] += 1
            
        except sqlite3.Error as e:
            print(f"❌ Failed to log event: {e}")
    
    def check_anomalies(self, event):
        """
        Basic anomaly detection
        In production, this would use statistical analysis and ML
        """
        # Example: Detect potential port scan
        cursor = self.db_conn.cursor()
        
        # Check if source IP has contacted many different ports recently
        cursor.execute("""
            SELECT COUNT(DISTINCT destination_port) as port_count
            FROM traffic_events
            WHERE source_ip = ?
            AND timestamp > datetime('now', '-5 minutes')
        """, (event['source_ip'],))
        
        result = cursor.fetchone()
        if result and result[0] > 20:  # More than 20 different ports
            self.create_alert(
                alert_type='port_scan',
                severity='medium',
                source_ip=event['source_ip'],
                description=f"Potential port scan detected from {event['source_ip']}",
                details=f"Contacted {result[0]} different ports in 5 minutes"
            )
    
    def create_alert(self, alert_type, severity, source_ip, description, details):
        """Create a security alert"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("""
                INSERT INTO security_alerts
                (timestamp, alert_type, severity, source_ip, description, details)
                VALUES (datetime('now'), ?, ?, ?, ?, ?)
            """, (alert_type, severity, source_ip, description, details))
            self.db_conn.commit()
            print(f"🚨 ALERT [{severity.upper()}]: {description}")
            
        except sqlite3.Error as e:
            print(f"❌ Failed to create alert: {e}")
    
    def update_statistics(self):
        """Update aggregated network statistics"""
        try:
            cursor = self.db_conn.cursor()
            
            # Calculate stats for the last minute
            cursor.execute("""
                INSERT INTO network_stats 
                (interval_start, interval_end, total_packets, total_bytes,
                 tcp_packets, udp_packets, icmp_packets, avg_packet_size)
                SELECT 
                    datetime('now', '-1 minute') as interval_start,
                    datetime('now') as interval_end,
                    COUNT(*) as total_packets,
                    SUM(packet_size) as total_bytes,
                    SUM(CASE WHEN protocol = 'TCP' THEN 1 ELSE 0 END) as tcp_packets,
                    SUM(CASE WHEN protocol = 'UDP' THEN 1 ELSE 0 END) as udp_packets,
                    SUM(CASE WHEN protocol = 'ICMP' THEN 1 ELSE 0 END) as icmp_packets,
                    AVG(packet_size) as avg_packet_size
                FROM traffic_events
                WHERE timestamp > datetime('now', '-1 minute')
            """)
            self.db_conn.commit()
            
        except sqlite3.Error as e:
            print(f"❌ Failed to update statistics: {e}")
    
    def print_status(self):
        """Print current monitoring status"""
        print(f"\n📊 Monitoring Status - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📦 Total packets captured: {self.packet_count}")
        print("📈 Protocol breakdown:")
        for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            print(f"   {protocol}: {count}")
    
    def cleanup(self, signum=None, frame=None):
        """Cleanup resources on exit"""
        print("\n\n🛑 Stopping monitor...")
        self.running = False
        if self.db_conn:
            self.db_conn.close()
        print("✅ Monitor stopped cleanly")
        sys.exit(0)
    
    def run(self):
        """Main monitoring loop"""
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)
        
        print("=" * 60)
        print("NetSecMonitor - Network Traffic Monitor")
        print("=" * 60)
        print("🚀 Starting network monitoring...")
        print("⚠️  NOTE: This demo uses simulated traffic data")
        print("💡 In production, replace simulate_traffic_event() with actual packet capture")
        print("Press Ctrl+C to stop\n")
        
        last_stats_update = time.time()
        last_status_print = time.time()
        
        while self.running:
            try:
                # Simulate capturing a packet
                # In production: use scapy.sniff() with packet callback
                event = self.simulate_traffic_event()
                
                # Log the event
                self.log_traffic_event(event)
                
                # Check for anomalies
                if self.packet_count % 10 == 0:  # Check every 10 packets
                    self.check_anomalies(event)
                
                # Update statistics every minute
                if time.time() - last_stats_update > 60:
                    self.update_statistics()
                    last_stats_update = time.time()
                
                # Print status every 10 seconds
                if time.time() - last_status_print > 10:
                    self.print_status()
                    last_status_print = time.time()
                
                # Simulate time between packets
                time.sleep(0.1)  # In production, this would be event-driven
                
            except Exception as e:
                print(f"❌ Error in monitoring loop: {e}")
                continue

if __name__ == "__main__":
    # Check for required privileges
    import os
    if os.geteuid() != 0:
        print("⚠️  WARNING: This script typically requires sudo for packet capture")
        print("📝 For this demo, we're using simulated data so sudo is not required")
        print("💡 In production with scapy, run with: sudo python monitor.py\n")
    
    # Check if database exists
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        print("Please run 'python init_db.py' first")
        sys.exit(1)
    
    # Start monitoring
    monitor = NetworkMonitor()
    monitor.run()
