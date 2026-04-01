"""
Alert Manager
Saves alerts to MySQL and provides retrieval methods.

Author: Pranjal Neupane
Date: April 2026
"""

import pymysql
import time
from datetime import datetime

DB_CONFIG = {
    'host':     'localhost',
    'user':     'pranjal_ids',
    'password': 'Pranjal@2026',
    'database': 'ids_database',
    'charset':  'utf8mb4',
}


class AlertManager:
    def __init__(self):
        self.connection = None
        self._connect()
        self._create_table()

    def _connect(self):
        try:
            self.connection = pymysql.connect(**DB_CONFIG)
            print('Connected to MySQL')
        except Exception as e:
            print(f'Database connection failed: {e}')

    def _create_table(self):
        if not self.connection:
            return
        query = """
        CREATE TABLE IF NOT EXISTS alerts (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            timestamp    DATETIME NOT NULL,
            source_ip    VARCHAR(45),
            dest_ip      VARCHAR(45),
            dest_port    INT,
            protocol     VARCHAR(10),
            attack_type  VARCHAR(20),
            confidence   FLOAT,
            risk_score   INT,
            risk_level   VARCHAR(10),
            method       VARCHAR(10),
            reason       TEXT,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        with self.connection.cursor() as cursor:
            cursor.execute(query)
        self.connection.commit()
        print('Alerts table ready')

    def save_alert(self, alert):
        if not self.connection:
            return False
        try:
            query = """
            INSERT INTO alerts
            (timestamp, source_ip, dest_ip, dest_port, protocol,
             attack_type, confidence_score, risk_score, severity,
             detection_method, additional_context)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            # Map risk_level to the enum values the table expects
            severity_map = {
                'CRITICAL': 'Critical',
                'HIGH':     'High',
                'MEDIUM':   'Medium',
                'LOW':      'Low',
            }
            values = (
                datetime.fromtimestamp(alert['timestamp']),
                alert['source_ip'],
                alert['dest_ip'],
                alert['dest_port'],
                alert['protocol'],
                alert['attack_type'],
                alert['confidence'],
                alert['risk_score'],
                severity_map.get(alert['risk_level'], 'Low'),
                alert['method'],
                alert['reason'],
            )
            with self.connection.cursor() as cursor:
                cursor.execute(query, values)
            self.connection.commit()
            return True
        except Exception as e:
            print(f'Failed to save alert: {e}')
            return False

    def get_recent_alerts(self, limit=20):
        if not self.connection:
            return []
        try:
            with self.connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s',
                    (limit,)
                )
                return cursor.fetchall()
        except Exception as e:
            print(f'Failed to retrieve alerts: {e}')
            return []

    def print_alert(self, alert):
        icons = {'CRITICAL': '[CRITICAL]', 'HIGH': '[HIGH]',
                 'MEDIUM': '[MEDIUM]', 'LOW': '[LOW]'}
        icon = icons.get(alert['risk_level'], '[?]')
        print(f"\n{icon} {alert['attack_type'].upper()} DETECTED")
        print(f"   Source : {alert['source_ip']}")
        print(f"   Target : {alert['dest_ip']}:{alert['dest_port']}")
        print(f"   Score  : {alert['risk_score']}/100")
        print(f"   Method : {alert['method'].upper()}")
        print(f"   Reason : {alert['reason']}")


if __name__ == '__main__':
    manager = AlertManager()
    test_alert = {
        'timestamp': time.time(), 'source_ip': '10.0.0.1',
        'dest_ip': '192.168.1.100', 'dest_port': 80, 'protocol': 'TCP',
        'attack_type': 'dos', 'confidence': 0.92, 'risk_score': 75,
        'risk_level': 'HIGH', 'method': 'rule',
        'reason': 'DoS detected: 110 packets/sec',
    }
    if manager.save_alert(test_alert):
        print('Alert saved to database')
    manager.print_alert(test_alert)
    alerts = manager.get_recent_alerts(limit=5)
    print(f'\nRetrieved {len(alerts)} alert(s) from database')
    print('Alert manager working!')
