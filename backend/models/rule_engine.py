"""
Rule-Based Detection Engine
Detects obvious attacks using predefined threshold rules.

Rules cover:
- DoS: high packet rate to same destination
- Port scan (Probe): many different ports scanned
- Brute force (R2L): repeated connections to auth ports
- Land attack: source IP == destination IP

Author: Pranjal Neupane
Date: April 2026
"""

from collections import defaultdict, deque
import time


class RuleEngine:
    def __init__(self):
        self.packet_counts = defaultdict(lambda: deque(maxlen=1000))
        self.port_trackers = defaultdict(set)
        self.auth_attempts = defaultdict(lambda: deque(maxlen=100))

        # Thresholds
        self.DOS_THRESHOLD        = 100  # packets/sec to same IP
        self.PORTSCAN_THRESHOLD   = 20   # unique ports in 10 seconds
        self.BRUTEFORCE_THRESHOLD = 10   # auth attempts in 30 seconds

        self.AUTH_PORTS = {22, 21, 23, 3389}

    def check_packet(self, packet):
        """
        Check packet against all rules.
        Returns dict if threat detected, None if clean.
        """
        now      = time.time()
        src_ip   = packet.get('source_ip', '')
        dst_ip   = packet.get('dest_ip', '')
        dst_port = packet.get('dest_port', 0)

        # Rule 1: Land attack
        if src_ip == dst_ip and src_ip != '' and src_ip != '127.0.0.1':
            return {
                'detected': True, 'attack_type': 'dos', 'confidence': 1.0,
                'reason': f'Land attack: source IP equals destination IP ({src_ip})'
            }

        self.packet_counts[dst_ip].append(now)

        # Rule 2: DoS detection
        recent = [t for t in self.packet_counts[dst_ip] if now - t <= 1.0]
        if len(recent) >= self.DOS_THRESHOLD:
            return {
                'detected': True, 'attack_type': 'dos',
                'confidence': min(len(recent) / self.DOS_THRESHOLD, 1.0),
                'reason': f'DoS: {len(recent)} packets/sec to {dst_ip}'
            }

        # Rule 3: Port scan detection
        self.port_trackers[src_ip].add(dst_port)
        if len(self.port_trackers[src_ip]) >= self.PORTSCAN_THRESHOLD:
            unique_ports = len(self.port_trackers[src_ip])
            self.port_trackers[src_ip].clear()
            return {
                'detected': True, 'attack_type': 'probe',
                'confidence': min(unique_ports / self.PORTSCAN_THRESHOLD, 1.0),
                'reason': f'Port scan: {unique_ports} unique ports from {src_ip}'
            }

        # Rule 4: Brute force on auth ports
        if dst_port in self.AUTH_PORTS:
            self.auth_attempts[src_ip].append(now)
            recent_auth = [t for t in self.auth_attempts[src_ip] if now - t <= 30.0]
            if len(recent_auth) >= self.BRUTEFORCE_THRESHOLD:
                return {
                    'detected': True, 'attack_type': 'r2l',
                    'confidence': min(len(recent_auth) / self.BRUTEFORCE_THRESHOLD, 1.0),
                    'reason': f'Brute force: {len(recent_auth)} attempts to port {dst_port} from {src_ip}'
                }

        return None


if __name__ == '__main__':
    engine = RuleEngine()

    # Test land attack
    result = engine.check_packet({
        'source_ip': '192.168.1.1', 'dest_ip': '192.168.1.1',
        'dest_port': 80, 'protocol': 'TCP'
    })
    print(f'Land attack: {result["attack_type"]} — {result["reason"]}')

    # Test DoS
    for i in range(110):
        result = engine.check_packet({
            'source_ip': '10.0.0.1', 'dest_ip': '192.168.1.100',
            'dest_port': 80, 'protocol': 'TCP', 'packet_size': 64
        })
    if result:
        print(f'DoS: {result["attack_type"]} — {result["reason"]}')

    # Test port scan
    scan_result = None
    for port in range(1, 25):
        r = engine.check_packet({
            'source_ip': '10.0.0.2', 'dest_ip': '192.168.1.200',
            'dest_port': port, 'protocol': 'TCP', 'packet_size': 64
        })
        if r:
            scan_result = r
            break
    if scan_result:
        print(f'Port scan: {scan_result["attack_type"]} — {scan_result["reason"]}')
    else:
        print('Port scan: not detected')

    print('Rule engine working!')
