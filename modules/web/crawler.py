"""
Web Crawler — BFS site mapper with form/link/email extraction
"""

import ssl
import re
import random
import time
import urllib.request
import urllib.error
import urllib.parse
from collections import deque
from typing import List, Dict, Set, Tuple, Optional

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 200, timeout: int = 8):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

        parsed = urllib.parse.urlparse(self.base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme

        self.visited: Set[str] = set()
        self.pages: List[Dict] = []
        self.forms: List[Dict] = []
        self.external_links: Set[str] = set()
        self.emails: Set[str] = set()
        self.js_files: Set[str] = set()
        self.css_files: Set[str] = set()
        self.images: Set[str] = set()
        self.errors: List[Tuple[str, str]] = []

    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _fetch(self, url: str) -> Tuple[int, str, Dict]:
        """Fetch URL, return (status, body, headers)."""
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": random.choice(UAS),
                "Accept": "text/html,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            })
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ssl_ctx()))
            resp = opener.open(req, timeout=self.timeout)
            body = resp.read().decode("utf-8", errors="ignore")
            headers = dict(resp.headers)
            return resp.getcode(), body, headers
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return e.code, body, {}
        except Exception as e:
            self.errors.append((url, str(e)[:50]))
            return 0, "", {}

    def _normalize_url(self, url: str, page_url: str) -> Optional[str]:
        """Normalize relative URL to absolute."""
        if not url or url.startswith(("#", "mailto:", "tel:", "data:", "javascript:")):
            return None

        # Handle relative URLs
        full = urllib.parse.urljoin(page_url, url)
        parsed = urllib.parse.urlparse(full)

        # Stay on same domain
        if parsed.netloc != self.domain:
            self.external_links.add(full)
            return None

        # Clean URL
        clean = parsed._replace(fragment="").geturl()
        return clean

    def _extract_links_regex(self, body: str, page_url: str) -> List[str]:
        """Extract links using regex (fallback when bs4 not available)."""
        links = []

        # href/src attributes
        for match in re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', body, re.I):
            url = self._normalize_url(match.group(1), page_url)
            if url:
                links.append(url)

        # Emails
        for email in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', body):
            self.emails.add(email)

        return links

    def _extract_links_bs4(self, body: str, page_url: str) -> List[str]:
        """Extract links using BeautifulSoup."""
        links = []
        soup = BeautifulSoup(body, "html.parser")

        # Links
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href")
            url = self._normalize_url(href, page_url) if href else None
            if url:
                links.append(url)

        # Scripts
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                full = urllib.parse.urljoin(page_url, src)
                self.js_files.add(full)
                url = self._normalize_url(src, page_url)
                if url:
                    links.append(url)

        # Images
        for tag in soup.find_all("img"):
            src = tag.get("src")
            if src:
                full = urllib.parse.urljoin(page_url, src)
                self.images.add(full)

        # CSS
        for tag in soup.find_all("link", rel="stylesheet"):
            href = tag.get("href")
            if href:
                full = urllib.parse.urljoin(page_url, href)
                self.css_files.add(full)

        # iframes
        for tag in soup.find_all("iframe"):
            src = tag.get("src")
            url = self._normalize_url(src, page_url) if src else None
            if url:
                links.append(url)

        # Forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urllib.parse.urljoin(page_url, action) if action else page_url
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                itype = inp.get("type", "text")
                value = inp.get("value", "")
                if name:
                    inputs.append({"name": name, "type": itype, "value": value})
            if inputs:
                self.forms.append({
                    "url": form_url,
                    "method": method,
                    "inputs": inputs,
                    "page": page_url,
                })

        # Emails
        for email in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', body):
            self.emails.add(email)

        return links

    def _extract_forms_regex(self, body: str, page_url: str):
        """Extract forms using regex (fallback)."""
        for match in re.finditer(
            r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?(\w+)["\']?[^>]*>(.*?)</form>',
            body, re.I | re.S
        ):
            action = match.group(1) or ""
            method = match.group(2).upper()
            form_body = match.group(3)
            form_url = urllib.parse.urljoin(page_url, action) if action else page_url

            inputs = []
            for inp_match in re.finditer(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?[^>]*(?:value=["\']([^"\']*)["\'])?',
                form_body, re.I
            ):
                inputs.append({
                    "name": inp_match.group(1),
                    "type": inp_match.group(2) or "text",
                    "value": inp_match.group(3) or "",
                })

            if inputs:
                self.forms.append({
                    "url": form_url, "method": method,
                    "inputs": inputs, "page": page_url,
                })

    def crawl(self) -> Dict:
        """BFS crawl the website."""
        print(f"\n  \033[96m[CRAWL]\033[0m Target: \033[97m{self.base_url}\033[0m")
        print(f"  \033[96m[CRAWL]\033[0m Max depth: {self.max_depth} | Max pages: {self.max_pages}")
        print(f"  \033[96m[CRAWL]\033[0m Parser: {'BeautifulSoup4' if HAS_BS4 else 'Regex (install bs4 for better results)'}\n")

        t0 = time.time()
        queue = deque([(self.base_url, 0)])
        self.visited.add(self.base_url)

        while queue and len(self.pages) < self.max_pages:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            code, body, headers = self._fetch(url)
            if code == 0 or not body:
                continue

            content_type = headers.get("Content-Type", "")
            if "text/html" not in content_type and "text/" not in content_type:
                continue

            title = ""
            title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            if title_match:
                title = title_match.group(1).strip()[:80]

            self.pages.append({
                "url": url, "status": code, "title": title,
                "depth": depth, "size": len(body),
            })

            indent = "  " * (depth + 1)
            status_color = "\033[92m" if code == 200 else "\033[93m" if code < 400 else "\033[91m"
            print(f"  {status_color}[{code}]\033[0m {indent}{url[-60:]}  \033[2m{title[:30]}\033[0m")

            # Extract links
            if HAS_BS4:
                links = self._extract_links_bs4(body, url)
            else:
                links = self._extract_links_regex(body, url)
                self._extract_forms_regex(body, url)

            for link in links:
                if link not in self.visited and len(self.visited) < self.max_pages * 2:
                    # Only crawl HTML-like URLs
                    if not any(link.lower().endswith(ext) for ext in
                              ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                               '.css', '.woff', '.woff2', '.ttf', '.eot',
                               '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip']):
                        self.visited.add(link)
                        queue.append((link, depth + 1))

        elapsed = time.time() - t0

        # Report
        print(f"\n\033[96m{'═' * 60}")
        print(f"  WEB CRAWLER RESULTS")
        print(f"{'═' * 60}\033[0m")
        print(f"  \033[97mTarget:\033[0m          {self.base_url}")
        print(f"  \033[97mPages Crawled:\033[0m   \033[92m{len(self.pages)}\033[0m")
        print(f"  \033[97mForms Found:\033[0m     \033[93m{len(self.forms)}\033[0m")
        print(f"  \033[97mExternal Links:\033[0m  {len(self.external_links)}")
        print(f"  \033[97mEmails Found:\033[0m    {len(self.emails)}")
        print(f"  \033[97mJS Files:\033[0m        {len(self.js_files)}")
        print(f"  \033[97mErrors:\033[0m          {len(self.errors)}")
        print(f"  \033[97mDuration:\033[0m        {elapsed:.1f}s")

        if self.forms:
            print(f"\n  \033[93mFORMS ({len(self.forms)}):\033[0m")
            for f in self.forms[:15]:
                params = ", ".join(i["name"] for i in f["inputs"])
                print(f"    \033[93m{f['method']}\033[0m {f['url'][:50]}")
                print(f"      Fields: {params}")

        if self.emails:
            print(f"\n  \033[92mEMAILS:\033[0m")
            for e in list(self.emails)[:20]:
                print(f"    {e}")

        if self.js_files:
            print(f"\n  \033[96mJS FILES ({len(self.js_files)}):\033[0m")
            for js in list(self.js_files)[:10]:
                print(f"    {js[-60:]}")

        print(f"\033[96m{'═' * 60}\033[0m\n")

        return {
            "pages": self.pages,
            "forms": self.forms,
            "external_links": list(self.external_links),
            "emails": list(self.emails),
            "js_files": list(self.js_files),
            "errors": self.errors,
        }
