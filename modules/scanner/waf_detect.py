import requests
from bs4 import BeautifulSoup
from core.colors import log_info, log_success, log_warning, log_danger

class WAFDetector:
    def __init__(self, target):
        self.target = target
        # Signatures of common WAFs
        self.waf_signatures = {
            "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "AWS WAF": ["x-amz-cf-id", "awselb"],
            "Akamai": ["akamai", "x-akamai"],
            "Imperva / Incapsula": ["incap_ses", "visid_incap"],
            "F5 BIG-IP": ["bigipserver", "f5"],
            "Sucuri": ["sucuri/cloudproxy", "x-sucuri"]
        }

    def detect(self):
        log_info(f"Scanning {self.target} for Web Application Firewalls (WAF)...")
        try:
            # We send a slightly suspicious payload to trigger WAF headers
            headers = {"User-Agent": "HydraStorm-Scanner/1.0"}
            response = requests.get(f"{self.target}/?id=1' OR '1'='1", headers=headers, timeout=10)
            
            detected_wafs = []
            
            # Check Headers
            headers_str = str(response.headers).lower()
            for waf, signatures in self.waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str:
                        if waf not in detected_wafs:
                            detected_wafs.append(waf)
            
            # Check Cookies
            cookies_str = str(response.cookies).lower()
            for waf, signatures in self.waf_signatures.items():
                for sig in signatures:
                    if sig in cookies_str:
                        if waf not in detected_wafs:
                            detected_wafs.append(waf)
                            
            # Check Body
            body_str = response.text.lower()
            if "cloudflare" in body_str and "Cloudflare" not in detected_wafs:
                detected_wafs.append("Cloudflare")

            if detected_wafs:
                for waf in detected_wafs:
                    log_warning(f"[WAF DETECTED] Target is protected by: {waf}")
                return detected_wafs
            else:
                log_success("No WAF detected. Target appears vulnerable.")
                return []
                
        except Exception as e:
            log_danger(f"Failed to scan WAF: {e}")
            return None
