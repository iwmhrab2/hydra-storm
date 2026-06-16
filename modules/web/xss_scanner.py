import requests
from bs4 import BeautifulSoup
from core.colors import log_info, log_success, log_warning, log_danger

class XSSScanner:
    def __init__(self, target):
        self.target = target
        self.payloads = [
            "<script>alert('XSS')</script>",
            "\"'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        self.visited_links = set()
        self.forms_found = []

    def crawl_target(self, url, depth=2):
        if depth == 0 or url in self.visited_links:
            return
        
        self.visited_links.add(url)
        log_info(f"Crawling: {url} (Depth: {depth})")
        
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            
            # Extract forms
            forms = soup.find_all("form")
            for form in forms:
                self.forms_found.append((url, form))
                
            # Extract links for crawling
            for link in soup.find_all("a", href=True):
                href = link['href']
                if href.startswith('/'):
                    href = self.target.rstrip('/') + href
                if href.startswith(self.target) and href not in self.visited_links:
                    self.crawl_target(href, depth - 1)
                    
        except Exception:
            pass

    def extract_forms(self, url):
        return [form for page_url, form in self.forms_found if page_url == url]

    def scan(self):
        log_info(f"Starting advanced XSS crawl & scan on {self.target}...")
        self.crawl_target(self.target, depth=3) # Crawl up to 3 links deep
        
        log_info(f"Found {len(self.forms_found)} unique forms across {len(self.visited_links)} pages.")

        vulnerable = False
        for page_url, form in self.forms_found:
            action = form.attrs.get("action", page_url)
            method = form.attrs.get("method", "get").lower()
            inputs = form.find_all("input")

            for payload in self.payloads:
                data = {}
                for input_tag in inputs:
                    if input_tag["type"] == "text" or input_tag["type"] == "search":
                        data[input_tag.get("name")] = payload
                    else:
                        data[input_tag.get("name")] = input_tag.get("value", "test")

                url = action if action.startswith("http") else self.target + action
                
                try:
                    if method == "post":
                        res = requests.post(url, data=data, timeout=5)
                    else:
                        res = requests.get(url, params=data, timeout=5)
                        
                    if payload in res.text:
                        log_success(f"[VULNERABLE] XSS detected in form #{i+1} at {url} with payload: {payload}")
                        vulnerable = True
                        break
                except Exception:
                    pass

        if not vulnerable:
            log_info("No XSS vulnerabilities detected.")
        return vulnerable

    def run(self):
        return self.scan()
