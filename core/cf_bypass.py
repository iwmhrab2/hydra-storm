from curl_cffi import requests as cffi_requests
from bs4 import BeautifulSoup
import re
from .colors import log_info, log_success, log_warning, log_danger

class CloudflareBypasser:
    def __init__(self, target_url, proxies=None):
        self.target_url = target_url
        self.proxies = proxies
        # Impersonate a real Chrome browser to bypass TLS fingerprinting (JA3/JA4)
        self.impersonate = "chrome110"
        self.session = cffi_requests.Session(impersonate=self.impersonate, proxies=self.proxies)
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        ]

    def get_headers(self):
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

    def bypass(self):
        log_info(f"Attempting to bypass Cloudflare for {self.target_url}...")
        try:
            # Initial request with perfect TLS fingerprint
            response = self.session.get(self.target_url, headers=self.get_headers(), timeout=15)
            
            # Check if we hit a JS challenge
            if response.status_code in [503, 403] and ("cloudflare" in response.text.lower() or "jschl" in response.text.lower()):
                log_warning("Cloudflare JS Challenge detected. Attempting to solve (headless)...")
                # Advanced logic to extract challenge params and post back would go here
                # For now, curl_cffi often solves standard UAM natively if cookies are handled right
                
                # Re-attempt with cookies grabbed from first hit
                response = self.session.get(self.target_url, headers=self.get_headers(), timeout=15)

            if response.status_code == 200:
                log_success("Cloudflare Bypass Successful! Session cookies established.")
                return {
                    "cookies": self.session.cookies.get_dict(),
                    "user_agent": self.session.headers.get("User-Agent")
                }
            else:
                log_danger(f"Bypass failed. Status Code: {response.status_code}")
                return None

        except Exception as e:
            log_danger(f"Bypass error: {e}")
            return None

    def get_session(self):
        return self.session
