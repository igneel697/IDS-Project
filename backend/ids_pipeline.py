"""
IDS Pipeline — Full End-to-End System
Connects packet capture -> detection engine -> alert manager.

Run this to start the live IDS.

Author: Pranjal Neupane
Date: April 2026
"""

import sys
import time
import signal

sys.path.append('./models')
sys.path.append('./capture')

from packet_capture import PacketCapture
from detection_engine import DetectionEngine
from alert_manager import AlertManager


class IDSPipeline:
    def __init__(self, interface='any'):
        print('=' * 60)
        print('REAL-TIME IDS STARTING')
        print('=' * 60)
        self.capture          = PacketCapture(interface=interface)
        self.detection_engine = DetectionEngine()
        self.alert_manager    = AlertManager()
        self.running          = False
        signal.signal(signal.SIGINT, self._shutdown)

    def start(self):
        self.running = True
        self.capture.start_capture()
        print('\nIDS running. Press Ctrl+C to stop.\n')

        while self.running:
            packet = self.capture.get_packet(timeout=1)
            if not packet:
                continue

            alert = self.detection_engine.process_packet(packet)
            if alert:
                self.alert_manager.save_alert(alert)
                self.alert_manager.print_alert(alert)

            stats = self.detection_engine.get_stats()
            if stats['total_packets'] % 100 == 0 and stats['total_packets'] > 0:
                print(f"[Stats] Packets: {stats['total_packets']} | "
                      f"Alerts: {stats['total_alerts']} | "
                      f"Queue: {self.capture.get_queue_size()}")

    def _shutdown(self, sig, frame):
        print('\n\nShutting down...')
        self.running = False
        self.capture.stop_capture()
        stats = self.detection_engine.get_stats()
        print(f'Final stats:')
        print(f'  Total packets : {stats["total_packets"]}')
        print(f'  Total alerts  : {stats["total_alerts"]}')
        print('IDS stopped cleanly')
        sys.exit(0)


if __name__ == '__main__':
    ids = IDSPipeline(interface='any')
    ids.start()
