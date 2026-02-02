#!/usr/bin/env python3
"""
Port Scanner Module
Scans for open ports and identifies services

SAFE FOR PERSONAL USE: Only scan localhost or networks you own
"""

import socket
import sqlite3
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

DB_PATH = "netsec_monitor.db"

# Common ports and their typical services
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

class PortScanner:
    """Network port scanner with service detection"""
    
    def __init__(self, target='127.0.0.1', timeout=1.0):
        self.target = target
        self.timeout = timeout
        self.db_conn = sqlite3.connect(DB_PATH)
        self.scan_timestamp = datetime.now().isoformat()
        
    def scan_port(self, port):
        """
        Scan a single port
        Returns: (port, status, service, banner, response_time)
        """
        start_time = time.time()
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((self.target, port))
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            if result == 0:
                # Port is open, try to get banner
                banner = self.grab_banner(sock, port)
                service = COMMON_PORTS.get(port, 'Unknown')
                sock.close()
                return (port, 'open', service, banner, response_time)
            else:
                sock.close()
                return (port, 'closed', None, None, response_time)
                
        except socket.timeout:
            return (port, 'filtered', None, None, self.timeout * 1000)
        except socket.error:
            return (port, 'closed', None, None, 0)
        except Exception as e:
            return (port, 'error', None, str(e), 0)
    
    def grab_banner(self, sock, port):
        """
        Attempt to grab service banner
        SAFE: Only reads response, doesn't send exploits
        """
        try:
            # Some services send banner immediately
            sock.settimeout(0.5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
        except:
            # Many services require a request first
            # For safety, we'll skip sending requests in this demo
            return None
    
    def save_result(self, port, status, service, banner, response_time):
        """Save scan result to database"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("""
                INSERT INTO port_scans 
                (scan_timestamp, target_ip, port, status, service, banner, response_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                self.scan_timestamp,
                self.target,
                port,
                status,
                service,
                banner,
                response_time
            ))
            self.db_conn.commit()
        except sqlite3.Error as e:
            print(f"❌ Database error: {e}")
    
    def scan_range(self, start_port, end_port, threads=50):
        """
        Scan a range of ports using multithreading
        """
        print(f"🔍 Scanning {self.target} ports {start_port}-{end_port}")
        print(f"⚙️  Using {threads} concurrent threads")
        print(f"⏱️  Timeout: {self.timeout}s per port\n")
        
        open_ports = []
        total_ports = end_port - start_port + 1
        scanned = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            # Process results as they complete
            for future in as_completed(future_to_port):
                port, status, service, banner, response_time = future.result()
                scanned += 1
                
                # Save to database
                self.save_result(port, status, service, banner, response_time)
                
                # Print progress
                if scanned % 100 == 0 or status == 'open':
                    progress = (scanned / total_ports) * 100
                    print(f"Progress: {progress:.1f}% ({scanned}/{total_ports})", end='\r')
                
                # Track open ports
                if status == 'open':
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'response_time': response_time
                    })
                    print(f"\n✅ Port {port} OPEN - {service or 'Unknown'}")
                    if banner:
                        print(f"   Banner: {banner[:100]}")
        
        print(f"\n\n{'='*60}")
        print("Scan Complete!")
        print(f"{'='*60}")
        return open_ports
    
    def generate_report(self, open_ports):
        """Generate scan report"""
        print(f"\n📊 Scan Report for {self.target}")
        print(f"🕐 Scan time: {self.scan_timestamp}")
        print(f"📈 Open ports found: {len(open_ports)}\n")
        
        if open_ports:
            print("Open Ports:")
            print(f"{'Port':<10} {'Service':<20} {'Response Time':<15}")
            print("-" * 45)
            for port_info in sorted(open_ports, key=lambda x: x['port']):
                print(f"{port_info['port']:<10} {port_info['service'] or 'Unknown':<20} {port_info['response_time']:.2f}ms")
        else:
            print("No open ports found in the scanned range")
        
        # Check for security concerns
        risky_ports = [p for p in open_ports if p['port'] in [21, 23, 445, 3389]]
        if risky_ports:
            print("\n⚠️  Security Notice:")
            print("The following potentially risky services were detected:")
            for port_info in risky_ports:
                print(f"   Port {port_info['port']}: {port_info['service']}")
    
    def close(self):
        """Close database connection"""
        if self.db_conn:
            self.db_conn.close()

def parse_port_range(port_string):
    """Parse port range string (e.g., '1-1024' or '80,443,8080')"""
    ports = []
    
    if '-' in port_string:
        # Range format: "1-1024"
        start, end = port_string.split('-')
        return int(start), int(end)
    elif ',' in port_string:
        # List format: "80,443,8080"
        ports = [int(p.strip()) for p in port_string.split(',')]
        return min(ports), max(ports)
    else:
        # Single port
        port = int(port_string)
        return port, port

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='NetSecMonitor Port Scanner - Scan for open ports and services'
    )
    parser.add_argument(
        '--target',
        default='127.0.0.1',
        help='Target IP address (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--ports',
        default='1-1024',
        help='Port range to scan (e.g., "1-1024", "80,443,8080") (default: 1-1024)'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Connection timeout in seconds (default: 1.0)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Number of concurrent threads (default: 50)'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("NetSecMonitor - Port Scanner")
    print("=" * 60)
    print()
    
    # Safety warning
    if args.target not in ['127.0.0.1', 'localhost', '::1']:
        print("⚠️  WARNING: Only scan systems you own or have permission to scan")
        response = input(f"Are you authorized to scan {args.target}? (yes/no): ")
        if response.lower() != 'yes':
            print("❌ Scan cancelled")
            exit(0)
    
    # Parse port range
    try:
        start_port, end_port = parse_port_range(args.ports)
    except ValueError:
        print(f"❌ Invalid port range: {args.ports}")
        exit(1)
    
    # Perform scan
    scanner = PortScanner(target=args.target, timeout=args.timeout)
    
    try:
        open_ports = scanner.scan_range(start_port, end_port, threads=args.threads)
        scanner.generate_report(open_ports)
    except KeyboardInterrupt:
        print("\n\n🛑 Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
    finally:
        scanner.close()
        print("\n✅ Scan complete. Results saved to database.")
