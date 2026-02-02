#!/usr/bin/env python3
"""
Anomaly Detection Engine
Identifies unusual network patterns and security threats

Uses statistical analysis and pattern matching to detect:
- Port scanning activity
- DDoS patterns
- Unusual traffic spikes
- Abnormal protocol usage
"""

import sqlite3
import statistics
from datetime import datetime, timedelta
from collections import defaultdict

DB_PATH = "netsec_monitor.db"

class AnomalyDetector:
    """
    Statistical anomaly detection for network security
    """
    
    def __init__(self):
        self.db_conn = sqlite3.connect(DB_PATH)
        self.baselines = {}
        self.load_baselines()
    
    def load_baselines(self):
        """Load baseline profiles from database"""
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT profile_name, metric_name, baseline_value, 
                   std_deviation, threshold_high, threshold_low
            FROM baseline_profiles
        """)
        
        for row in cursor.fetchall():
            key = f"{row[0]}_{row[1]}"
            self.baselines[key] = {
                'baseline': row[2],
                'std_dev': row[3],
                'threshold_high': row[4],
                'threshold_low': row[5]
            }
    
    def establish_baseline(self, profile_name, metric_name, lookback_hours=24):
        """
        Establish baseline for a metric based on historical data
        Uses mean and standard deviation
        """
        cursor = self.db_conn.cursor()
        
        # Example: Traffic volume baseline
        if metric_name == 'packets_per_minute':
            cursor.execute("""
                SELECT COUNT(*) as packet_count
                FROM traffic_events
                WHERE timestamp > datetime('now', ?)
                GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
            """, (f'-{lookback_hours} hours',))
            
            values = [row[0] for row in cursor.fetchall()]
            
            if len(values) > 10:  # Need sufficient data
                mean = statistics.mean(values)
                std_dev = statistics.stdev(values)
                
                # Set thresholds at 3 standard deviations
                threshold_high = mean + (3 * std_dev)
                threshold_low = max(0, mean - (3 * std_dev))
                
                # Save to database
                cursor.execute("""
                    INSERT OR REPLACE INTO baseline_profiles
                    (profile_name, metric_name, baseline_value, std_deviation,
                     threshold_high, threshold_low)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (profile_name, metric_name, mean, std_dev, 
                      threshold_high, threshold_low))
                
                self.db_conn.commit()
                
                print(f"✅ Baseline established for {metric_name}")
                print(f"   Mean: {mean:.2f}, Std Dev: {std_dev:.2f}")
                print(f"   Alert thresholds: {threshold_low:.2f} - {threshold_high:.2f}")
                
                return True
        
        return False
    
    def detect_port_scan(self, lookback_minutes=5):
        """
        Detect potential port scanning activity
        Criteria: Single source IP contacting many different ports
        """
        cursor = self.db_conn.cursor()
        
        cursor.execute("""
            SELECT 
                source_ip,
                COUNT(DISTINCT destination_port) as unique_ports,
                COUNT(*) as total_attempts,
                GROUP_CONCAT(DISTINCT destination_port) as ports
            FROM traffic_events
            WHERE timestamp > datetime('now', ?)
            GROUP BY source_ip
            HAVING unique_ports > 20
        """, (f'-{lookback_minutes} minutes',))
        
        alerts_created = 0
        for row in cursor.fetchall():
            source_ip = row[0]
            unique_ports = row[1]
            total_attempts = row[2]
            
            # Create alert
            self.create_alert(
                alert_type='port_scan',
                severity='high' if unique_ports > 50 else 'medium',
                source_ip=source_ip,
                description=f"Potential port scan detected from {source_ip}",
                details=f"Contacted {unique_ports} unique ports with {total_attempts} attempts in {lookback_minutes} minutes"
            )
            alerts_created += 1
        
        return alerts_created
    
    def detect_traffic_spike(self):
        """
        Detect unusual traffic volume spikes
        Compares current traffic to baseline
        """
        cursor = self.db_conn.cursor()
        
        # Get current minute's traffic
        cursor.execute("""
            SELECT COUNT(*) as packet_count
            FROM traffic_events
            WHERE timestamp > datetime('now', '-1 minute')
        """)
        
        current_count = cursor.fetchone()[0]
        
        # Check against baseline
        baseline_key = 'normal_traffic_packets_per_minute'
        if baseline_key in self.baselines:
            baseline = self.baselines[baseline_key]
            
            if current_count > baseline['threshold_high']:
                severity = 'critical' if current_count > baseline['threshold_high'] * 2 else 'high'
                
                self.create_alert(
                    alert_type='traffic_spike',
                    severity=severity,
                    source_ip=None,
                    description="Unusual traffic volume spike detected",
                    details=f"Current: {current_count} packets/min, Normal baseline: {baseline['baseline']:.0f} packets/min"
                )
                return True
        
        return False
    
    def detect_unusual_protocol(self):
        """
        Detect unusual protocol distribution
        Identifies protocols that are rarely seen
        """
        cursor = self.db_conn.cursor()
        
        # Get protocol distribution for last hour
        cursor.execute("""
            SELECT 
                protocol,
                COUNT(*) as count,
                COUNT(*) * 100.0 / (SELECT COUNT(*) FROM traffic_events 
                                     WHERE timestamp > datetime('now', '-1 hour')) as percentage
            FROM traffic_events
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY protocol
            HAVING percentage > 30 AND protocol NOT IN ('TCP', 'UDP', 'HTTP', 'HTTPS')
        """)
        
        alerts_created = 0
        for row in cursor.fetchall():
            protocol = row[0]
            count = row[1]
            percentage = row[2]
            
            self.create_alert(
                alert_type='unusual_protocol',
                severity='medium',
                source_ip=None,
                description=f"Unusual protocol usage: {protocol}",
                details=f"{protocol} comprises {percentage:.1f}% of traffic ({count} packets)"
            )
            alerts_created += 1
        
        return alerts_created
    
    def detect_failed_connections(self):
        """
        Detect high rate of failed connections
        May indicate brute force attempts or scanning
        """
        cursor = self.db_conn.cursor()
        
        # Look for IPs with many SYN packets but few established connections
        cursor.execute("""
            SELECT 
                source_ip,
                destination_ip,
                destination_port,
                COUNT(*) as syn_count
            FROM traffic_events
            WHERE timestamp > datetime('now', '-5 minutes')
            AND flags LIKE '%SYN%'
            GROUP BY source_ip, destination_ip, destination_port
            HAVING syn_count > 50
        """)
        
        alerts_created = 0
        for row in cursor.fetchall():
            source_ip = row[0]
            dest_ip = row[1]
            dest_port = row[2]
            syn_count = row[3]
            
            self.create_alert(
                alert_type='connection_flood',
                severity='high',
                source_ip=source_ip,
                description=f"High connection attempt rate from {source_ip}",
                details=f"{syn_count} SYN packets to {dest_ip}:{dest_port} in 5 minutes"
            )
            alerts_created += 1
        
        return alerts_created
    
    def detect_data_exfiltration(self):
        """
        Detect potential data exfiltration
        Large outbound data transfers to unusual destinations
        """
        cursor = self.db_conn.cursor()
        
        cursor.execute("""
            SELECT 
                source_ip,
                destination_ip,
                SUM(packet_size) as total_bytes,
                COUNT(*) as packet_count
            FROM traffic_events
            WHERE timestamp > datetime('now', '-10 minutes')
            AND source_ip LIKE '192.168.%'  -- Internal network
            AND destination_ip NOT LIKE '192.168.%'  -- External destination
            GROUP BY source_ip, destination_ip
            HAVING total_bytes > 10485760  -- 10MB
        """)
        
        alerts_created = 0
        for row in cursor.fetchall():
            source_ip = row[0]
            dest_ip = row[1]
            total_bytes = row[2]
            packet_count = row[3]
            
            mb_transferred = total_bytes / 1048576
            
            self.create_alert(
                alert_type='data_exfiltration',
                severity='high',
                source_ip=source_ip,
                description=f"Large data transfer detected",
                details=f"{source_ip} sent {mb_transferred:.2f}MB to {dest_ip} ({packet_count} packets)"
            )
            alerts_created += 1
        
        return alerts_created
    
    def create_alert(self, alert_type, severity, source_ip, description, details):
        """Create security alert in database"""
        try:
            cursor = self.db_conn.cursor()
            
            # Check if similar alert exists recently (avoid duplicates)
            cursor.execute("""
                SELECT id FROM security_alerts
                WHERE alert_type = ?
                AND source_ip = ?
                AND timestamp > datetime('now', '-10 minutes')
                AND status = 'open'
            """, (alert_type, source_ip))
            
            if cursor.fetchone():
                return  # Alert already exists
            
            # Create new alert
            cursor.execute("""
                INSERT INTO security_alerts
                (timestamp, alert_type, severity, source_ip, description, details, status)
                VALUES (datetime('now'), ?, ?, ?, ?, ?, 'open')
            """, (alert_type, severity, source_ip, description, details))
            
            self.db_conn.commit()
            
            # Print to console
            print(f"\n🚨 ALERT CREATED [{severity.upper()}]")
            print(f"   Type: {alert_type}")
            print(f"   {description}")
            print(f"   Details: {details}\n")
            
        except sqlite3.Error as e:
            print(f"❌ Failed to create alert: {e}")
    
    def run_all_detections(self):
        """Run all anomaly detection checks"""
        print("🔍 Running anomaly detection checks...\n")
        
        total_alerts = 0
        
        # Port scan detection
        alerts = self.detect_port_scan()
        total_alerts += alerts
        if alerts:
            print(f"   ✅ Port scan detection: {alerts} alert(s)")
        
        # Traffic spike detection
        if self.detect_traffic_spike():
            total_alerts += 1
            print(f"   ✅ Traffic spike detection: 1 alert")
        
        # Unusual protocol detection
        alerts = self.detect_unusual_protocol()
        total_alerts += alerts
        if alerts:
            print(f"   ✅ Unusual protocol detection: {alerts} alert(s)")
        
        # Failed connections
        alerts = self.detect_failed_connections()
        total_alerts += alerts
        if alerts:
            print(f"   ✅ Connection flood detection: {alerts} alert(s)")
        
        # Data exfiltration
        alerts = self.detect_data_exfiltration()
        total_alerts += alerts
        if alerts:
            print(f"   ✅ Data exfiltration detection: {alerts} alert(s)")
        
        if total_alerts == 0:
            print("   ✅ No anomalies detected - all systems normal")
        
        return total_alerts
    
    def close(self):
        """Close database connection"""
        if self.db_conn:
            self.db_conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("NetSecMonitor - Anomaly Detection Engine")
    print("=" * 60)
    print()
    
    detector = AnomalyDetector()
    
    try:
        # Establish baselines if needed
        print("📊 Establishing traffic baselines...")
        detector.establish_baseline('normal_traffic', 'packets_per_minute', lookback_hours=24)
        
        print("\n" + "=" * 60)
        
        # Run detection
        total_alerts = detector.run_all_detections()
        
        print("\n" + "=" * 60)
        print(f"Detection complete. {total_alerts} total alert(s) created.")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\n🛑 Detection interrupted")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        detector.close()
