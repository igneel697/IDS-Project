"""
Feature Extraction Module
Converts raw packets into the 20 NSL-KDD features the ML models expect.

Approach:
- Maintains a sliding window of the last 100 packets
- Calculates statistical features (rates, counts, error rates)
- Maps packet fields to the same 20 features used in training

Author: Pranjal Neupane
Date: April 2026
"""

import numpy as np
from collections import deque
import time


class FeatureExtractor:
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.packet_window = deque(maxlen=window_size)

        # Protocol encoding to match training data
        self.protocol_map = {'TCP': 0, 'UDP': 1, 'OTHER': 2}

        # Service mapping based on destination port
        self.service_map = {
            80: 'http', 443: 'https', 21: 'ftp', 22: 'ssh',
            23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop3',
            143: 'imap', 3306: 'mysql', 8080: 'http_alt'
        }

        # Flag encoding
        self.flag_map = {
            'SF': 0, 'S0': 1, 'REJ': 2, 'RSTO': 3,
            'SH': 4, 'S1': 5, 'S2': 6, 'S3': 7, 'OTH': 8,
        }

    def add_packet(self, packet):
        self.packet_window.append(packet)

    def extract_features(self, packet):
        """
        Extract the 20 NSL-KDD features from a packet.
        Returns numpy array of shape (1, 20).

        Feature order matches training exactly:
        ['duration', 'protocol_type', 'service', 'flag',
         'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
         'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
         'root_shell', 'num_file_creations',
         'count', 'srv_count', 'serror_rate', 'rerror_rate', 'diff_srv_rate']
        """
        self.add_packet(packet)
        window = list(self.packet_window)

        # Basic features
        duration      = 0
        protocol_type = self.protocol_map.get(packet.get('protocol', 'OTHER'), 2)
        service       = self._get_service(packet.get('dest_port', 0))
        flag          = self.flag_map.get('SF', 0)
        src_bytes     = packet.get('packet_size', 0)
        dst_bytes     = 0
        land          = 1 if packet.get('source_ip') == packet.get('dest_ip') else 0
        wrong_fragment= 0
        urgent        = 0

        # Content features
        hot               = 1 if packet.get('dest_port', 0) in [80, 443, 22, 21] else 0
        num_failed_logins = 0
        logged_in         = 1 if packet.get('dest_port', 0) in [22, 23, 21] else 0
        num_compromised   = 0
        root_shell        = 0
        num_file_creations= 0

        # Traffic features from sliding window
        dst_ip   = packet.get('dest_ip', '')
        dst_port = packet.get('dest_port', 0)

        count     = sum(1 for p in window if p.get('dest_ip') == dst_ip)
        srv_count = sum(1 for p in window if p.get('dest_port') == dst_port)

        syn_errors  = sum(1 for p in window
                         if p.get('dest_port', 0) == 0 and p.get('protocol') == 'TCP')
        serror_rate = syn_errors / max(count, 1)

        rej_errors  = sum(1 for p in window if p.get('packet_size', 0) > 65000)
        rerror_rate = rej_errors / max(count, 1)

        services_in_window = [p.get('dest_port') for p in window
                              if p.get('dest_ip') == dst_ip]
        diff_services = len(set(services_in_window))
        diff_srv_rate = diff_services / max(len(services_in_window), 1)

        features = np.array([[
            duration, protocol_type, service, flag,
            src_bytes, dst_bytes, land, wrong_fragment, urgent,
            hot, num_failed_logins, logged_in, num_compromised,
            root_shell, num_file_creations,
            count, srv_count, serror_rate, rerror_rate, diff_srv_rate
        ]], dtype=float)

        return features

    def _get_service(self, port):
        services = list(self.service_map.keys())
        if port in services:
            return services.index(port)
        return len(services)


if __name__ == '__main__':
    extractor = FeatureExtractor(window_size=100)
    test_packet = {
        'timestamp': time.time(), 'source_ip': '192.168.1.100',
        'dest_ip': '8.8.8.8', 'source_port': 54321,
        'dest_port': 80, 'protocol': 'TCP', 'packet_size': 512
    }
    features = extractor.extract_features(test_packet)
    print(f'Features extracted: shape = {features.shape}')
    print(f'Values: {features[0]}')
    print('Feature extraction working!')
