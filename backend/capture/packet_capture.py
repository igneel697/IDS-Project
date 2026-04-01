"""
Packet Capture Module — captures live traffic using tshark
Author: Pranjal Neupane
"""

import subprocess, logging, time
from queue import Queue
import threading

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PacketCapture:
    def __init__(self, interface='any', buffer_size=10000):
        self.interface        = interface
        self.buffer_size      = buffer_size
        self.packet_queue     = Queue(maxsize=buffer_size)
        self.is_running       = False
        self.capture_thread   = None
        self.tshark_process   = None
        self.packets_captured = 0
        self.packets_dropped  = 0

    def start_capture(self):
        if self.is_running:
            return False
        self.is_running       = True
        self.packets_captured = 0
        self.packets_dropped  = 0
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        logger.info(f'Started capture on: {self.interface}')
        return True

    def stop_capture(self):
        if not self.is_running:
            return False
        self.is_running = False
        if self.tshark_process:
            self.tshark_process.terminate()
            self.tshark_process.wait(timeout=5)
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info(f'Stopped. Captured: {self.packets_captured}')
        return True

    def _capture_packets(self):
        cmd = ['tshark', '-i', self.interface,
               '-T', 'fields',
               '-e', 'frame.time_epoch',
               '-e', 'ip.src',
               '-e', 'ip.dst',
               '-e', 'tcp.srcport',
               '-e', 'tcp.dstport',
               '-e', 'udp.srcport',
               '-e', 'udp.dstport',
               '-e', 'ip.proto',
               '-e', 'frame.len',
               '-E', 'separator=,',
               '-l']
        try:
            self.tshark_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, bufsize=1)
            for line in self.tshark_process.stdout:
                if not self.is_running:
                    break
                packet = self._parse_packet(line.strip())
                if packet:
                    self.packets_captured += 1
                    try:
                        self.packet_queue.put_nowait(packet)
                    except:
                        self.packets_dropped += 1
        except FileNotFoundError:
            logger.error('tshark not found: sudo apt install tshark')
        except Exception as e:
            logger.error(f'Capture error: {e}')
        finally:
            self.is_running = False

    def _parse_packet(self, line):
        try:
            parts = line.split(',')
            if len(parts) < 9:
                return None
            src_ip, dst_ip = parts[1], parts[2]
            if not src_ip or not dst_ip:
                return None
            if parts[3] and parts[4]:
                protocol = 'TCP'
                src_port, dst_port = int(parts[3]), int(parts[4])
            elif parts[5] and parts[6]:
                protocol = 'UDP'
                src_port, dst_port = int(parts[5]), int(parts[6])
            else:
                protocol = 'OTHER'
                src_port = dst_port = 0
            return {
                'timestamp':   float(parts[0]) if parts[0] else time.time(),
                'source_ip':   src_ip,
                'dest_ip':     dst_ip,
                'source_port': src_port,
                'dest_port':   dst_port,
                'protocol':    protocol,
                'packet_size': int(parts[8]) if parts[8] else 0
            }
        except Exception as e:
            logger.debug(f'Parse error: {e}')
            return None

    def get_packet(self, timeout=1):
        try:
            return self.packet_queue.get(timeout=timeout)
        except:
            return None

    def get_stats(self):
        return {
            'is_running':       self.is_running,
            'packets_captured': self.packets_captured,
            'packets_dropped':  self.packets_dropped,
            'queue_size':       self.packet_queue.qsize(),
        }


if __name__ == '__main__':
    capture = PacketCapture(interface='any')
    print('Starting 30-second capture test...')
    print('Open a browser or run: ping -c 10 google.com')
    capture.start_capture()
    start = time.time()
    count = 0
    while time.time() - start < 30:
        pkt = capture.get_packet(timeout=1)
        if pkt:
            count += 1
            if count % 10 == 0:
                print(f'Packet {count}: {pkt["source_ip"]} -> '
                      f'{pkt["dest_ip"]} ({pkt["protocol"]})')
    capture.stop_capture()
    stats = capture.get_stats()
    print(f'\nDone. Captured: {stats["packets_captured"]}  '
          f'Dropped: {stats["packets_dropped"]}')
