"""
Detection Engine
Combines rule-based and ML-based detection into one pipeline.

Flow per packet:
1. Check rules first (fast)
2. If no rule triggered, run ML models
3. Calculate risk score
4. Return final verdict

Author: Pranjal Neupane
Date: April 2026
"""

from rule_engine import RuleEngine
from ml_engine import MLEngine
from feature_extraction import FeatureExtractor
from risk_scoring import RiskScorer
import time


class DetectionEngine:
    def __init__(self):
        print('Loading detection engine...')
        self.rule_engine       = RuleEngine()
        self.ml_engine         = MLEngine()
        self.feature_extractor = FeatureExtractor(window_size=100)
        self.risk_scorer       = RiskScorer()
        self.total_packets     = 0
        self.total_alerts      = 0
        print('Detection engine ready')

    def process_packet(self, packet):
        """
        Process one packet through the full detection pipeline.
        Returns alert dict if threat found, None if normal.
        """
        self.total_packets += 1
        source_ip = packet.get('source_ip', 'unknown')

        # Step 1: Rule check
        rule_result = self.rule_engine.check_packet(packet)
        if rule_result and rule_result['detected']:
            attack_type = rule_result['attack_type']
            confidence  = rule_result['confidence']
            method      = 'rule'
            reason      = rule_result['reason']
        else:
            # Step 2: ML check
            features   = self.feature_extractor.extract_features(packet)
            ml_result  = self.ml_engine.predict(features)
            attack_type= ml_result['final_prediction']
            confidence = ml_result['final_confidence']
            method     = 'ml'
            reason     = (f"RF: {ml_result['rf_prediction']} "
                         f"({ml_result['rf_confidence']*100:.0f}%), "
                         f"NB: {ml_result['nb_prediction']} "
                         f"({ml_result['nb_confidence']*100:.0f}%)")
            if attack_type == 'normal'or confidence < 0.70:
                return None

        # Step 3: Risk score
        risk = self.risk_scorer.calculate_score(attack_type, confidence, source_ip)
        if risk['score'] == 0:
            return None

        self.total_alerts += 1
        return {
            'timestamp':   time.time(),
            'source_ip':   source_ip,
            'dest_ip':     packet.get('dest_ip', ''),
            'dest_port':   packet.get('dest_port', 0),
            'protocol':    packet.get('protocol', ''),
            'attack_type': attack_type,
            'confidence':  confidence,
            'risk_score':  risk['score'],
            'risk_level':  risk['level'],
            'method':      method,
            'reason':      reason,
        }

    def get_stats(self):
        return {
            'total_packets': self.total_packets,
            'total_alerts':  self.total_alerts,
        }


if __name__ == '__main__':
    engine = DetectionEngine()
    test_packets = [
        {'source_ip': '192.168.1.10', 'dest_ip': '8.8.8.8',
         'source_port': 54000, 'dest_port': 80,
         'protocol': 'TCP', 'packet_size': 512},
        {'source_ip': '192.168.1.1', 'dest_ip': '192.168.1.1',
         'source_port': 80, 'dest_port': 80,
         'protocol': 'TCP', 'packet_size': 64},
    ]
    print('\nProcessing test packets:')
    for pkt in test_packets:
        result = engine.process_packet(pkt)
        if result:
            print(f'  ALERT: {result["attack_type"].upper()} | '
                  f'Score: {result["risk_score"]} ({result["risk_level"]})')
        else:
            print(f'  Normal traffic from {pkt["source_ip"]}')
    print(f'\nStats: {engine.get_stats()}')
    print('Detection engine working!')
