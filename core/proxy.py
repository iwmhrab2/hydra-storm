import requests
from bs4 import BeautifulSoup
import concurrent.futures
from .colors import log_info, log_success, log_warning, log_danger
import random

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.proxy_sources = [
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
        ]

    def scrape_proxies(self):
        log_info("Scraping fresh proxies from global sources...")
        raw_proxies = set()
        for source in self.proxy_sources:
            try:
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    lines = response.text.strip().split('\\n')
                    raw_proxies.update([line.strip() for line in lines if ':' in line])
            except Exception as e:
                log_warning(f"Failed to scrape {source}: {e}")
        
        self.proxies = list(raw_proxies)
        log_success(f"Scraped {len(self.proxies)} raw proxies.")
        return self.proxies

    def check_proxy(self, proxy):
        try:
            proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
            response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=5)
            if response.status_code == 200:
                return proxy
        except:
            pass
        return None

    def validate_proxies(self, max_workers=50):
        if not self.proxies:
            log_danger("No proxies to validate. Scrape first.")
            return []

        log_info(f"Validating {len(self.proxies)} proxies with {max_workers} threads...")
        valid_proxies = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(self.check_proxy, self.proxies)
            for result in results:
                if result:
                    valid_proxies.append(result)

        self.proxies = valid_proxies
        log_success(f"Found {len(self.proxies)} LIVE proxies ready for war.")
        return self.proxies

    def get_random_proxy(self):
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    def get_proxy_dict(self):
        proxy = self.get_random_proxy()
        if proxy:
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        return None
