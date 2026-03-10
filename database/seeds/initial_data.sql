-- ================================================================
-- Initial Data for IDS Database
-- ================================================================

USE ids_database;

-- ================================================================
-- Insert Default Configuration
-- ================================================================
INSERT INTO configuration (config_key, config_value, data_type, category, description) VALUES
-- Detection Thresholds
('dos_threshold', '500', 'integer', 'detection', 'Packets per second threshold for DoS detection'),
('brute_force_threshold', '5', 'integer', 'detection', 'Failed login attempts threshold'),
('brute_force_window', '30', 'integer', 'detection', 'Time window in seconds for brute force'),
('port_scan_threshold', '20', 'integer', 'detection', 'Unique ports threshold for port scan'),
('port_scan_window', '60', 'integer', 'detection', 'Time window in seconds for port scan'),

-- Risk Scoring Weights (must sum to 100)
('risk_weight_attack_type', '30', 'integer', 'risk_scoring', 'Weight percentage for attack type'),
('risk_weight_frequency', '25', 'integer', 'risk_scoring', 'Weight percentage for frequency'),
('risk_weight_service', '25', 'integer', 'risk_scoring', 'Weight percentage for service criticality'),
('risk_weight_reputation', '20', 'integer', 'risk_scoring', 'Weight percentage for IP reputation'),

-- System Settings
('alert_retention_days', '90', 'integer', 'system', 'Days to retain alerts before archival'),
('dashboard_refresh_interval', '5', 'integer', 'system', 'Dashboard auto-refresh in seconds'),
('max_packet_buffer', '10000', 'integer', 'system', 'Maximum packets to buffer'),
('log_level', 'INFO', 'string', 'system', 'Logging level: DEBUG, INFO, WARNING, ERROR');

-- ================================================================
-- Insert Service Mappings (Port-to-Service with Criticality)
-- ================================================================
INSERT INTO service_mapping (port_number, service_name, protocol, criticality_score, description, is_well_known) VALUES
-- Critical Services (25 points)
(22, 'SSH', 'TCP', 25, 'Secure Shell - Remote access', TRUE),
(80, 'HTTP', 'TCP', 25, 'Hypertext Transfer Protocol', TRUE),
(443, 'HTTPS', 'TCP', 25, 'HTTP Secure', TRUE),
(3306, 'MySQL', 'TCP', 25, 'MySQL Database Server', TRUE),
(5432, 'PostgreSQL', 'TCP', 25, 'PostgreSQL Database Server', TRUE),

-- High Priority Services (22-23 points)
(23, 'Telnet', 'TCP', 22, 'Telnet Protocol (unencrypted)', TRUE),
(25, 'SMTP', 'TCP', 22, 'Simple Mail Transfer Protocol', TRUE),
(445, 'SMB', 'TCP', 23, 'Server Message Block', TRUE),
(3389, 'RDP', 'TCP', 22, 'Remote Desktop Protocol', TRUE),

-- Medium Priority Services (20 points)
(20, 'FTP-DATA', 'TCP', 20, 'FTP Data Transfer', TRUE),
(21, 'FTP', 'TCP', 20, 'File Transfer Protocol', TRUE),
(110, 'POP3', 'TCP', 20, 'Post Office Protocol v3', TRUE),
(143, 'IMAP', 'TCP', 20, 'Internet Message Access Protocol', TRUE),
(8080, 'HTTP-ALT', 'TCP', 20, 'HTTP Alternate Port', TRUE),

-- Lower Priority Services (18 points)
(53, 'DNS', 'UDP', 18, 'Domain Name System', TRUE),
(123, 'NTP', 'UDP', 18, 'Network Time Protocol', TRUE),

-- Default/Unknown (15 points) - will be used for ports not in this table
(0, 'UNKNOWN', 'TCP', 15, 'Unknown or custom service', FALSE);

-- ================================================================
-- Insert Whitelist Entries
-- ================================================================
INSERT INTO whitelist (ip_address, description, added_by, is_active) VALUES
('127.0.0.1', 'Localhost IPv4 - always trusted', 'system', TRUE),
('::1', 'Localhost IPv6 - always trusted', 'system', TRUE),
('192.168.1.1', 'Default gateway (adjust for your network)', 'system', TRUE);

-- Note: Adjust the third entry based on your actual gateway IP
-- You can remove it or update it later

-- ================================================================
-- Verification Queries
-- ================================================================
SELECT COUNT(*) as config_count FROM configuration;
SELECT COUNT(*) as service_count FROM service_mapping;
SELECT COUNT(*) as whitelist_count FROM whitelist;

SELECT 'Database initialized successfully!' as status;
