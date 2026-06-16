"""
Hydra Storm v7.0 — Vulnerability Scanner
Checks for common misconfigurations, exposed files, missing security headers.
"""

import random
import re
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/125.0.2535.67",
]

# Severity levels
HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"
INFO   = "INFO"


class VulnScanner:
    """Scan for common web vulnerabilities and misconfigurations."""

    def __init__(self, target: str) -> None:
        self.target: str = target if target.startswith("http") else f"https://{target}"
        self.target = self.target.rstrip("/")
        self.vulns: List[Dict[str, str]] = []
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------
    def _get(self, path: str = "", follow: bool = True) -> Optional[Tuple[int, Dict[str, str], str]]:
        """GET request, return (status, headers, body)."""
        url = f"{self.target}{path}"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "*/*",
            })
            if not follow:
                # Build opener that doesn't follow redirects
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *a, **kw):
                        return None
                opener = urllib.request.build_opener(
                    NoRedirect,
                    urllib.request.HTTPSHandler(context=self._ctx),
                )
                resp = opener.open(req, timeout=10)
            else:
                resp = urllib.request.urlopen(req, timeout=10, context=self._ctx)
            headers = {k.lower(): v for k, v in resp.getheaders()}
            body = resp.read().decode("utf-8", errors="replace")[:10000]
            return (resp.status, headers, body)
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
            try:
                body = e.read().decode("utf-8", errors="replace")[:10000]
            except Exception:
                body = ""
            return (e.code, headers, body)
        except Exception:
            return None

    # ------------------------------------------------------------------
    def _add_vuln(self, severity: str, title: str, description: str, evidence: str = "") -> None:
        self.vulns.append({
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
        })

    # ------------------------------------------------------------------
    def _check_git(self) -> None:
        """Check for exposed .git directory."""
        resp = self._get("/.git/HEAD")
        if resp and resp[0] == 200:
            body = resp[2]
            if "ref:" in body or "refs/" in body:
                self._add_vuln(HIGH, "Exposed .git Directory",
                    "The .git directory is publicly accessible. Full source code can be reconstructed.",
                    f"/.git/HEAD returned: {body[:100]}")
                return
        resp = self._get("/.git/config")
        if resp and resp[0] == 200 and "[core]" in resp[2]:
            self._add_vuln(HIGH, "Exposed .git/config",
                "Git config is publicly accessible, may leak repo URLs and credentials.",
                "/.git/config is readable")

    # ------------------------------------------------------------------
    def _check_env(self) -> None:
        """Check for exposed .env file."""
        for path in ["/.env", "/.env.local", "/.env.production", "/.env.backup"]:
            resp = self._get(path)
            if resp and resp[0] == 200:
                body = resp[2]
                if any(kw in body.upper() for kw in ["DB_", "API_KEY", "SECRET", "PASSWORD", "DATABASE_URL", "AWS_"]):
                    self._add_vuln(HIGH, f"Exposed {path}",
                        f"Environment file {path} is publicly accessible and contains sensitive variables.",
                        f"Contains sensitive keys: {[k for k in ['DB_', 'API_KEY', 'SECRET', 'PASSWORD'] if k in body.upper()]}")
                    return

    # ------------------------------------------------------------------
    def _check_directory_listing(self) -> None:
        """Check if directory listing is enabled."""
        for path in ["/", "/images/", "/uploads/", "/static/", "/assets/", "/backup/", "/files/"]:
            resp = self._get(path)
            if resp and resp[0] == 200:
                body = resp[2].lower()
                if any(sig in body for sig in ["index of /", "directory listing", "<title>index of", "parent directory"]):
                    self._add_vuln(MEDIUM, "Directory Listing Enabled",
                        f"Directory listing is enabled at {path}, exposing file structure.",
                        f"Path: {path}")
                    return

    # ------------------------------------------------------------------
    def _check_server_disclosure(self) -> None:
        """Check for server version disclosure."""
        resp = self._get("/")
        if not resp:
            return
        _, headers, _ = resp
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")

        if server:
            # Check if version number is included
            if re.search(r"[\d]+\.[\d]+", server):
                self._add_vuln(LOW, "Server Version Disclosure",
                    f"Server header reveals version information: {server}",
                    f"Server: {server}")
        if powered:
            self._add_vuln(LOW, "X-Powered-By Disclosure",
                f"X-Powered-By header reveals backend technology: {powered}",
                f"X-Powered-By: {powered}")

    # ------------------------------------------------------------------
    def _check_security_headers(self) -> None:
        """Check for missing security headers."""
        resp = self._get("/")
        if not resp:
            return
        _, headers, _ = resp

        checks = [
            ("x-frame-options", MEDIUM, "Missing X-Frame-Options",
             "Site may be vulnerable to clickjacking attacks."),
            ("content-security-policy", MEDIUM, "Missing Content-Security-Policy",
             "No CSP header. Site may be vulnerable to XSS and data injection."),
            ("strict-transport-security", MEDIUM, "Missing Strict-Transport-Security (HSTS)",
             "HSTS not set. Users may be vulnerable to MITM via HTTP downgrade."),
            ("x-content-type-options", LOW, "Missing X-Content-Type-Options",
             "Browser may MIME-sniff responses, enabling certain attacks."),
            ("x-xss-protection", INFO, "Missing X-XSS-Protection",
             "Legacy XSS protection header not set (modern CSP is preferred)."),
            ("referrer-policy", INFO, "Missing Referrer-Policy",
             "No referrer policy set. Referrer data may leak to third parties."),
            ("permissions-policy", INFO, "Missing Permissions-Policy",
             "No permissions policy set. Browser features are unrestricted."),
        ]

        missing = []
        for header, severity, title, desc in checks:
            if header not in headers:
                self._add_vuln(severity, title, desc, f"Header '{header}' not found in response")
                missing.append(header)

    # ------------------------------------------------------------------
    def _check_default_pages(self) -> None:
        """Check for default credential/admin pages."""
        paths = [
            ("/admin/", "Admin panel"),
            ("/admin/login", "Admin login"),
            ("/administrator/", "Administrator panel"),
            ("/wp-login.php", "WordPress login"),
            ("/wp-admin/", "WordPress admin"),
            ("/user/login", "User login (Drupal)"),
            ("/manager/html", "Tomcat Manager"),
            ("/phpmyadmin/", "phpMyAdmin"),
            ("/adminer.php", "Adminer"),
            ("/solr/", "Apache Solr"),
            ("/jenkins/", "Jenkins"),
            ("/grafana/", "Grafana"),
            ("/kibana/", "Kibana"),
            ("/api/swagger", "Swagger API docs"),
            ("/swagger-ui.html", "Swagger UI"),
            ("/api-docs", "API documentation"),
        ]

        for path, name in paths:
            resp = self._get(path)
            if resp and resp[0] in (200, 301, 302):
                self._add_vuln(MEDIUM if resp[0] == 200 else LOW,
                    f"{name} Accessible",
                    f"{name} page found at {path} (status {resp[0]})",
                    f"{path} → {resp[0]}")

    # ------------------------------------------------------------------
    def _check_phpinfo(self) -> None:
        """Check for phpinfo() exposure."""
        for path in ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php"]:
            resp = self._get(path)
            if resp and resp[0] == 200 and "phpinfo()" in resp[2]:
                self._add_vuln(HIGH, "phpinfo() Exposed",
                    f"phpinfo() page found at {path}. Leaks full server config, env vars, PHP settings.",
                    f"Path: {path}")
                return

    # ------------------------------------------------------------------
    def _check_xmlrpc(self) -> None:
        """Check for WordPress XML-RPC."""
        resp = self._get("/xmlrpc.php")
        if resp and resp[0] == 200:
            if "XML-RPC server accepts POST requests only" in resp[2] or "xmlrpc" in resp[2].lower():
                self._add_vuln(MEDIUM, "WordPress XML-RPC Enabled",
                    "XML-RPC is accessible. Can be abused for brute-force and DDoS amplification.",
                    "/xmlrpc.php is responding")

    # ------------------------------------------------------------------
    def _check_open_redirect(self) -> None:
        """Check for open redirect potential."""
        payloads = [
            "?url=https://evil.com",
            "?redirect=https://evil.com",
            "?next=https://evil.com",
            "?return=https://evil.com",
            "?goto=https://evil.com",
            "?dest=https://evil.com",
            "?rurl=https://evil.com",
            "/redirect?url=https://evil.com",
            "/login?next=https://evil.com",
        ]
        for payload in payloads:
            resp = self._get(payload, follow=False)
            if resp and resp[0] in (301, 302, 303, 307, 308):
                location = resp[1].get("location", "")
                if "evil.com" in location:
                    self._add_vuln(MEDIUM, "Open Redirect",
                        f"Target follows redirects to arbitrary URLs via parameter.",
                        f"Payload: {payload} → Location: {location}")
                    return

    # ------------------------------------------------------------------
    def _check_cors(self) -> None:
        """Check for CORS misconfiguration."""
        try:
            url = self.target
            req = urllib.request.Request(url, headers={
                "User-Agent": random.choice(USER_AGENTS),
                "Origin": "https://evil.com",
            })
            resp = urllib.request.urlopen(req, timeout=10, context=self._ctx)
            acao = dict(resp.getheaders()).get("Access-Control-Allow-Origin", "")

            if acao == "*":
                self._add_vuln(MEDIUM, "CORS Wildcard Origin",
                    "Access-Control-Allow-Origin is set to *, allowing any origin.",
                    f"ACAO: {acao}")
            elif "evil.com" in acao:
                self._add_vuln(HIGH, "CORS Origin Reflection",
                    "Server reflects arbitrary Origin in ACAO header — credentials can be stolen.",
                    f"Sent Origin: evil.com → ACAO: {acao}")

            acac = dict(resp.getheaders()).get("Access-Control-Allow-Credentials", "")
            if acac.lower() == "true" and (acao == "*" or "evil.com" in acao):
                self._add_vuln(HIGH, "CORS with Credentials",
                    "CORS allows credentials with permissive origin — full account takeover possible.",
                    f"ACAO: {acao}, ACAC: {acac}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    def check_common_vulns(self) -> List[Dict[str, str]]:
        """Run all vulnerability checks."""
        self.vulns = []

        print(f"\n  🔎 Vulnerability Scan — {self.target}")
        print(f"  {'='*60}")

        checks = [
            ("Exposed .git directory",     self._check_git),
            ("Exposed .env file",          self._check_env),
            ("Directory listing",          self._check_directory_listing),
            ("Server version disclosure",  self._check_server_disclosure),
            ("Security headers",           self._check_security_headers),
            ("Default / admin pages",      self._check_default_pages),
            ("phpinfo() exposure",         self._check_phpinfo),
            ("WordPress XML-RPC",          self._check_xmlrpc),
            ("Open redirect",              self._check_open_redirect),
            ("CORS misconfiguration",      self._check_cors),
        ]

        for i, (name, fn) in enumerate(checks, 1):
            print(f"  [{i:2d}/{len(checks)}] Checking {name}...")
            try:
                fn()
            except Exception as e:
                print(f"         ⚠ Error: {e}")

        self._print_report()
        return self.vulns

    # ------------------------------------------------------------------
    def _print_report(self) -> None:
        """Print formatted vulnerability report."""
        severity_icons = {
            HIGH:   "🔴",
            MEDIUM: "🟡",
            LOW:    "🟢",
            INFO:   "ℹ️ ",
        }
        severity_order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

        sorted_vulns = sorted(self.vulns, key=lambda v: severity_order.get(v["severity"], 99))

        print(f"\n  {'='*70}")
        print(f"  VULNERABILITY REPORT — {self.target}")
        print(f"  Total findings: {len(self.vulns)}")

        counts = {}
        for v in self.vulns:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1
        summary_parts = [f"{severity_icons.get(s, '?')} {s}: {c}" for s, c in
                         sorted(counts.items(), key=lambda x: severity_order.get(x[0], 99))]
        print(f"  Summary: {' | '.join(summary_parts)}")
        print(f"  {'='*70}\n")

        for v in sorted_vulns:
            icon = severity_icons.get(v["severity"], "?")
            print(f"  {icon} [{v['severity']}] {v['title']}")
            print(f"     {v['description']}")
            if v.get("evidence"):
                print(f"     Evidence: {v['evidence']}")
            print()

        print(f"  {'='*70}\n")
