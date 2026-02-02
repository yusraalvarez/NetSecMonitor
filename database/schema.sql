-- NetSecMonitor Database Schema
-- Designed for efficient time-series security event storage and analysis

-- Traffic Events Table
-- Stores all network packets captured and analyzed
CREATE TABLE IF NOT EXISTS traffic_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT NOT NULL,  -- TCP, UDP, ICMP, etc.
    packet_size INTEGER,
    flags TEXT,  -- TCP flags if applicable
    payload_preview TEXT,  -- First 100 chars (sanitized)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast time-based queries
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_source ON traffic_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_dest ON traffic_events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_protocol ON traffic_events(protocol);

-- Security Alerts Table
-- Stores detected anomalies and security events
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_type TEXT NOT NULL,  -- port_scan, anomaly, suspicious_traffic, etc.
    severity TEXT NOT NULL,  -- low, medium, high, critical
    source_ip TEXT,
    destination_ip TEXT,
    description TEXT NOT NULL,
    details TEXT,  -- JSON string with additional context
    status TEXT DEFAULT 'open',  -- open, investigating, resolved, false_positive
    resolved_at DATETIME,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);

-- Port Scan Results Table
-- Stores results from port scanning activities
CREATE TABLE IF NOT EXISTS port_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    target_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,  -- open, closed, filtered
    service TEXT,  -- HTTP, SSH, MySQL, etc.
    banner TEXT,  -- Service banner if available
    response_time REAL,  -- milliseconds
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON port_scans(target_ip);
CREATE INDEX IF NOT EXISTS idx_scans_port ON port_scans(port);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON port_scans(scan_timestamp);

-- Network Statistics Table
-- Aggregated statistics for performance monitoring
CREATE TABLE IF NOT EXISTS network_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    interval_start DATETIME NOT NULL,
    interval_end DATETIME NOT NULL,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    tcp_packets INTEGER DEFAULT 0,
    udp_packets INTEGER DEFAULT 0,
    icmp_packets INTEGER DEFAULT 0,
    other_packets INTEGER DEFAULT 0,
    unique_sources INTEGER DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    avg_packet_size REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_stats_interval ON network_stats(interval_start, interval_end);

-- Protocol Distribution Table
-- Tracks protocol usage over time
CREATE TABLE IF NOT EXISTS protocol_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    protocol TEXT NOT NULL,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_protocol_timestamp ON protocol_stats(timestamp);

-- Baseline Profiles Table
-- Stores normal behavior baselines for anomaly detection
CREATE TABLE IF NOT EXISTS baseline_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_name TEXT UNIQUE NOT NULL,
    metric_name TEXT NOT NULL,
    baseline_value REAL NOT NULL,
    std_deviation REAL,
    threshold_high REAL,
    threshold_low REAL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- System Configuration Table
-- Stores monitoring configuration and settings
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default configuration
INSERT OR IGNORE INTO config (key, value, description) VALUES 
    ('monitoring_enabled', 'true', 'Enable/disable traffic monitoring'),
    ('alert_threshold_high', '1000', 'Packets per minute to trigger high severity alert'),
    ('alert_threshold_medium', '500', 'Packets per minute to trigger medium severity alert'),
    ('scan_interval', '300', 'Port scan interval in seconds'),
    ('retention_days', '30', 'Days to retain traffic data'),
    ('anomaly_sensitivity', '2.0', 'Standard deviations for anomaly detection');

-- Views for common queries

-- Recent Alerts View
CREATE VIEW IF NOT EXISTS recent_alerts AS
SELECT 
    id,
    timestamp,
    alert_type,
    severity,
    source_ip,
    destination_ip,
    description,
    status
FROM security_alerts
WHERE status != 'resolved'
ORDER BY timestamp DESC
LIMIT 100;

-- Top Talkers View (most active IPs in last hour)
CREATE VIEW IF NOT EXISTS top_talkers AS
SELECT 
    source_ip,
    COUNT(*) as packet_count,
    SUM(packet_size) as total_bytes,
    MAX(timestamp) as last_seen
FROM traffic_events
WHERE timestamp > datetime('now', '-1 hour')
GROUP BY source_ip
ORDER BY packet_count DESC
LIMIT 20;

-- Protocol Distribution View (last 24 hours)
CREATE VIEW IF NOT EXISTS protocol_distribution AS
SELECT 
    protocol,
    COUNT(*) as count,
    SUM(packet_size) as total_bytes,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM traffic_events WHERE timestamp > datetime('now', '-24 hours')), 2) as percentage
FROM traffic_events
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY protocol
ORDER BY count DESC;
