"""
Risk Scoring Module
Scores each threat 0-100 based on attack type, confidence, and frequency.

Author: Pranjal Neupane
Date: April 2026
"""

from collections import defaultdict, deque
import time

BASE_SCORES = {
    'u2r':    90,
    'r2l':    70,
    'dos':    60,
    'probe':  40,
    'normal': 0,
}

RISK_LEVELS = {
    (86, 100): 'CRITICAL',
    (61, 85):  'HIGH',
    (31, 60):  'MEDIUM',
    (0,  30):  'LOW',
}


class RiskScorer:
    def __init__(self, frequency_window=60):
        self.frequency_window   = frequency_window
        self.detection_history  = defaultdict(lambda: deque(maxlen=1000))

    def calculate_score(self, attack_type, confidence, source_ip):
        base_score = BASE_SCORES.get(attack_type, 0)
        if base_score == 0:
            return {'score': 0, 'level': 'LOW', 'attack_type': attack_type}

        # Confidence multiplier (0.5 to 1.0)
        confidence_multiplier = 0.5 + (confidence * 0.5)

        # Frequency multiplier
        now = time.time()
        self.detection_history[source_ip].append(now)
        recent = [t for t in self.detection_history[source_ip]
                 if now - t <= self.frequency_window]
        frequency_count = len(recent)

        if frequency_count >= 10:
            frequency_multiplier = 1.3
        elif frequency_count >= 5:
            frequency_multiplier = 1.15
        else:
            frequency_multiplier = 1.0

        score = min(int(base_score * confidence_multiplier * frequency_multiplier), 100)

        level = 'LOW'
        for (low, high), lbl in RISK_LEVELS.items():
            if low <= score <= high:
                level = lbl
                break

        return {
            'score':       score,
            'level':       level,
            'attack_type': attack_type,
        }


if __name__ == '__main__':
    scorer = RiskScorer()
    tests = [
        ('u2r', 0.95, '10.0.0.1'),
        ('dos', 0.80, '10.0.0.2'),
        ('probe', 0.60, '10.0.0.3'),
        ('r2l', 0.50, '10.0.0.4'),
        ('normal', 0.99, '10.0.0.5'),
    ]
    print(f'{"Attack":<10} {"Confidence":<12} {"Score":<8} {"Level"}')
    print('-' * 42)
    for attack, conf, ip in tests:
        result = scorer.calculate_score(attack, conf, ip)
        print(f'{attack:<10} {conf:<12.0%} {result["score"]:<8} {result["level"]}')
    print('Risk scoring working!')
