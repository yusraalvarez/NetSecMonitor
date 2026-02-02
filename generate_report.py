#!/usr/bin/env python3
"""
Security Report Generator
Generates comprehensive security reports from collected data
"""

import sqlite3
import argparse
from datetime import datetime, timedelta

DB_PATH = "netsec_monitor.db"

class ReportGenerator:
    """Generate security and network analysis reports"""
    
    def __init__(self):
        self.db_conn = sqlite3.connect(DB_PATH)
        self.db_conn.row_factory = sqlite3.Row
    
    def generate_summary_report(self, hours=24):
        """Generate executive summary report"""
        cursor = self.db_conn.cursor()
        
        print("=" * 70)
        print(f"NetSecMonitor - Security Summary Report")
        print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Time period: Last {hours} hours")
        print("=" * 70)
        print()
        
        # Traffic Overview
        print("📊 TRAFFIC OVERVIEW")
        print("-" * 70)
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_packets,
                SUM(packet_size) as total_bytes,
                COUNT(DISTINCT source_ip) as unique_sources,
                COUNT(DISTINCT destination_ip) as unique_destinations
            FROM traffic_events
            WHERE timestamp > datetime('now', ?)
        """, (f'-{hours} hours',))
        
        row = cursor.fetchone()
        print(f"Total Packets:        {row['total_packets']:,}")
        print(f"Total Data:           {row['total_bytes'] / 1048576:.2f} MB")
        print(f"Unique Source IPs:    {row['unique_sources']}")
        print(f"Unique Dest IPs:      {row['unique_destinations']}")
        print()
        
        # Protocol Distribution
        print("🔍 PROTOCOL DISTRIBUTION")
        print("-" * 70)
        
        cursor.execute("""
            SELECT protocol, COUNT(*) as count,
                   COUNT(*) * 100.0 / (SELECT COUNT(*) FROM traffic_events 
                                        WHERE timestamp > datetime('now', ?)) as percentage
            FROM traffic_events
            WHERE timestamp > datetime('now', ?)
            GROUP BY protocol
            ORDER BY count DESC
            LIMIT 10
        """, (f'-{hours} hours', f'-{hours} hours'))
        
        for row in cursor.fetchall():
            bar = '█' * int(row['percentage'])
            print(f"{row['protocol']:<15} {row['count']:>8,} packets  {row['percentage']:>5.1f}% {bar}")
        print()
        
        # Security Alerts
        print("🚨 SECURITY ALERTS")
        print("-" * 70)
        
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM security_alerts
            WHERE timestamp > datetime('now', ?)
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END
        """, (f'-{hours} hours',))
        
        total_alerts = 0
        for row in cursor.fetchall():
            print(f"{row['severity'].upper():<12} {row['count']:>5} alert(s)")
            total_alerts += row['count']
        
        if total_alerts == 0:
            print("No alerts in this period ✅")
        print()
        
        # Top Alert Types
        if total_alerts > 0:
            print("📋 TOP ALERT TYPES")
            print("-" * 70)
            
            cursor.execute("""
                SELECT alert_type, COUNT(*) as count
                FROM security_alerts
                WHERE timestamp > datetime('now', ?)
                GROUP BY alert_type
                ORDER BY count DESC
                LIMIT 5
            """, (f'-{hours} hours',))
            
            for row in cursor.fetchall():
                print(f"{row['alert_type']:<30} {row['count']:>5} occurrence(s)")
            print()
        
        # Top Talkers
        print("💻 TOP 10 TRAFFIC SOURCES")
        print("-" * 70)
        
        cursor.execute("""
            SELECT source_ip, COUNT(*) as packets, SUM(packet_size) as bytes
            FROM traffic_events
            WHERE timestamp > datetime('now', ?)
            GROUP BY source_ip
            ORDER BY packets DESC
            LIMIT 10
        """, (f'-{hours} hours',))
        
        print(f"{'IP Address':<20} {'Packets':>12} {'Data':>12}")
        print("-" * 70)
        for row in cursor.fetchall():
            mb = row['bytes'] / 1048576
            print(f"{row['source_ip']:<20} {row['packets']:>12,} {mb:>11.2f} MB")
        print()
        
        # Recent Critical Alerts
        cursor.execute("""
            SELECT timestamp, alert_type, description, source_ip
            FROM security_alerts
            WHERE timestamp > datetime('now', ?)
            AND severity IN ('critical', 'high')
            ORDER BY timestamp DESC
            LIMIT 10
        """, (f'-{hours} hours',))
        
        critical_alerts = cursor.fetchall()
        
        if critical_alerts:
            print("⚠️  CRITICAL/HIGH SEVERITY ALERTS (Most Recent)")
            print("-" * 70)
            for row in critical_alerts:
                print(f"[{row['timestamp']}] {row['alert_type']}")
                print(f"  {row['description']}")
                if row['source_ip']:
                    print(f"  Source: {row['source_ip']}")
                print()
        
        # Recommendations
        print("💡 RECOMMENDATIONS")
        print("-" * 70)
        
        if total_alerts == 0:
            print("✅ No security issues detected in this period")
        else:
            print("⚠️  Review and investigate security alerts listed above")
        
        # Check for port scans
        cursor.execute("""
            SELECT COUNT(*) FROM security_alerts
            WHERE alert_type = 'port_scan'
            AND timestamp > datetime('now', ?)
        """, (f'-{hours} hours',))
        
        if cursor.fetchone()[0] > 0:
            print("⚠️  Port scanning activity detected - review firewall rules")
        
        # Check for traffic spikes
        cursor.execute("""
            SELECT COUNT(*) FROM security_alerts
            WHERE alert_type = 'traffic_spike'
            AND timestamp > datetime('now', ?)
        """, (f'-{hours} hours',))
        
        if cursor.fetchone()[0] > 0:
            print("⚠️  Unusual traffic spikes detected - investigate source")
        
        print()
        print("=" * 70)
        print("End of Report")
        print("=" * 70)
    
    def close(self):
        """Close database connection"""
        if self.db_conn:
            self.db_conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate security reports from NetSecMonitor data'
    )
    parser.add_argument(
        '--last',
        default='24h',
        help='Time period for report (e.g., 24h, 7d, 30d)'
    )
    
    args = parser.parse_args()
    
    # Parse time period
    time_str = args.last.lower()
    if time_str.endswith('h'):
        hours = int(time_str[:-1])
    elif time_str.endswith('d'):
        hours = int(time_str[:-1]) * 24
    else:
        print(f"❌ Invalid time format: {time_str}")
        print("Use format like: 24h, 7d, 30d")
        exit(1)
    
    # Generate report
    generator = ReportGenerator()
    try:
        generator.generate_summary_report(hours)
    except Exception as e:
        print(f"❌ Error generating report: {e}")
    finally:
        generator.close()
