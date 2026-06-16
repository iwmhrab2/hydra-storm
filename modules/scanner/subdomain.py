"""
Hydra Storm v1.0 — Subdomain Enumerator
Bruteforce + Certificate Transparency (crt.sh) + Cloudflare detection.
"""

import json
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 500+ subdomain prefixes — the fat list
# ---------------------------------------------------------------------------
TOP_SUBDOMAINS: List[str] = [
    # Tier 1 — you see these everywhere
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    # Admin & management
    "admin", "administrator", "cpanel", "whm", "webmin", "panel", "manage",
    "manager", "dashboard", "portal", "control", "controlpanel", "console",
    "sysadmin", "root", "superadmin", "master",
    # Development
    "dev", "dev1", "dev2", "dev3", "develop", "development", "developer",
    "sandbox", "test", "test1", "test2", "test3", "testing", "qa", "qa1",
    "qa2", "uat", "staging", "stage", "stage1", "stage2", "preprod",
    "pre-prod", "preview", "demo", "lab", "labs", "beta", "alpha",
    "canary", "nightly", "experimental",
    # API & services
    "api", "api1", "api2", "api3", "api-v1", "api-v2", "rest", "graphql",
    "grpc", "gateway", "gw", "service", "services", "svc", "microservice",
    "ws", "websocket", "wss", "rpc", "soap",
    # Cloud & infrastructure
    "cloud", "aws", "azure", "gcp", "gcloud", "s3", "cdn", "cdn1", "cdn2",
    "edge", "node", "node1", "node2", "cluster", "k8s", "kubernetes",
    "docker", "container", "registry", "harbor", "helm",
    # CI/CD & DevOps
    "ci", "cd", "jenkins", "gitlab", "github", "bitbucket", "bamboo",
    "circleci", "travis", "drone", "argo", "argocd", "pipeline",
    "build", "deploy", "release", "artifact", "artifacts", "nexus",
    "sonar", "sonarqube", "terraform", "ansible", "puppet", "chef",
    # Git & version control
    "git", "svn", "hg", "mercurial", "repo", "repos", "repository",
    "code", "source", "src",
    # Database
    "db", "db1", "db2", "db3", "database", "mysql", "postgres", "postgresql",
    "mongo", "mongodb", "redis", "elastic", "elasticsearch", "es",
    "cassandra", "couchdb", "influx", "influxdb", "neo4j", "mariadb",
    "mssql", "sql", "oracle", "memcached",
    # Mail
    "email", "imap", "pop3", "exchange", "outlook", "postfix", "sendmail",
    "newsletter", "lists", "mailing", "mailman", "roundcube",
    # VPN & security
    "vpn", "vpn1", "vpn2", "openvpn", "wireguard", "ssl", "sslvpn",
    "proxy", "proxy1", "proxy2", "socks", "tor", "firewall", "fw",
    "waf", "ids", "ips", "siem", "security", "auth", "sso", "oauth",
    "login", "signin", "signup", "register", "cas", "ldap", "ad",
    "radius", "2fa", "mfa", "vault", "secrets", "certbot",
    # Monitoring & logging
    "monitor", "monitoring", "nagios", "zabbix", "grafana", "prometheus",
    "kibana", "logstash", "elk", "splunk", "datadog", "newrelic",
    "sentry", "status", "health", "healthcheck", "uptime", "pingdom",
    "pagerduty", "alert", "alerts", "log", "logs", "logging",
    # Web servers & apps
    "app", "app1", "app2", "app3", "apps", "application", "web", "web1",
    "web2", "web3", "www1", "www2", "www3", "site", "sites",
    "frontend", "front", "backend", "back", "server", "server1",
    "server2", "host", "host1", "host2",
    # Content & media
    "blog", "news", "press", "media", "video", "videos", "stream",
    "streaming", "live", "tv", "radio", "podcast", "img", "images",
    "image", "photo", "photos", "pic", "pics", "thumb", "thumbnails",
    "static", "assets", "asset", "content", "upload", "uploads",
    "download", "downloads", "dl", "files", "file", "docs", "doc",
    "documents", "pdf", "wiki", "kb", "knowledge",
    # E-commerce
    "shop", "store", "ecommerce", "cart", "checkout", "pay", "payment",
    "payments", "billing", "invoice", "order", "orders",
    # Communication
    "chat", "im", "irc", "slack", "teams", "meet", "meeting",
    "conference", "zoom", "webex", "voip", "sip", "pbx", "asterisk",
    "freeswitch", "forum", "forums", "community", "discuss", "discourse",
    "support", "help", "helpdesk", "ticket", "tickets", "jira",
    "zendesk", "freshdesk",
    # CMS & frameworks
    "wp", "wordpress", "joomla", "drupal", "magento", "shopify",
    "woocommerce", "laravel", "django", "rails", "express",
    "strapi", "ghost", "cms",
    # Analytics & tracking
    "analytics", "stats", "statistics", "track", "tracking", "pixel",
    "tag", "gtm", "ga",
    # Internal & corp
    "internal", "intranet", "extranet", "corp", "corporate", "company",
    "office", "hr", "erp", "crm", "salesforce",
    # Mobile
    "mobile", "m", "mobi", "android", "ios", "pwa",
    # Search & cache
    "search", "solr", "sphinx", "algolia", "cache", "varnish", "memcache",
    "squid",
    # Storage & backup
    "storage", "nas", "san", "backup", "bak", "archive", "archives",
    "old", "legacy", "deprecated", "temp", "tmp",
    # Network
    "ns", "dns", "router", "switch", "gateway", "gw1", "gw2", "nat",
    "dhcp", "ntp", "snmp", "radius1", "tacacs",
    # Misc services
    "crm", "erp", "bi", "tableau", "powerbi", "redash", "metabase",
    "superset", "airflow", "kafka", "rabbitmq", "mq", "queue",
    "celery", "worker", "cron", "scheduler", "job", "jobs",
    "task", "tasks",
    # Geo / regional
    "us", "eu", "uk", "de", "fr", "jp", "cn", "au", "ca", "br",
    "in", "sg", "hk", "kr",
    "us-east", "us-west", "eu-west", "eu-central", "ap-south",
    "ap-northeast", "ap-southeast",
    # Numbered instances
    "srv1", "srv2", "srv3", "srv4", "srv5",
    "vps1", "vps2", "vps3",
    "vm1", "vm2", "vm3",
    "box1", "box2", "box3",
    "dc1", "dc2", "dc3",
    "rack1", "rack2",
    # Extra common
    "remote", "connect", "access", "jump", "jumpbox", "bastion",
    "citrix", "rdp", "ssh", "sftp", "rsync",
    "autodiscover", "autoconfig", "lyncdiscover",
    "sip", "sipfed", "enterpriseregistration", "enterpriseenrollment",
    "selector1", "selector2", "dkim", "spf", "dmarc",
    "_dmarc", "_domainkey",
    "calendar", "cal", "contacts", "address",
    "time", "ntp1", "ntp2",
    "pki", "ca", "crl", "ocsp", "cert", "certs",
    "update", "updates", "patch", "patches",
    "mirror", "mirrors", "repo1", "repo2",
    "maven", "npm", "pypi", "gem", "nuget", "composer",
    "go", "rust", "cargo",
    "grafana1", "prometheus1", "elastic1",
    "traefik", "envoy", "istio", "consul", "nomad",
    "minio", "ceph",
    "hadoop", "spark", "hive", "pig", "hbase",
    "presto", "druid", "clickhouse",
    "ldap1", "ldap2", "ad1", "ad2",
    "exchange1", "exchange2",
    "webdav", "carddav", "caldav",
    "matrix", "element", "mattermost", "rocket",
    "nextcloud", "owncloud", "seafile",
    "gitea", "gogs", "cgit",
    "redmine", "trac", "bugzilla", "mantis",
    "phpmyadmin", "pma", "adminer",
    "pgadmin", "mongoexpress",
    "portainer", "rancher", "cockpit",
    "awx", "tower", "foreman", "katello",
    "observium", "librenms", "cacti", "mrtg",
    "prtg", "icinga", "checkmk",
    "guacamole", "shellinabox", "wetty",
    "jupyter", "notebook", "colab",
    "airflow1", "dag", "dags",
    "vault1", "consul1",
    "haproxy", "lb", "lb1", "lb2", "loadbalancer",
    "failover", "standby", "replica", "slave", "primary", "secondary",
]

# Cloudflare IP ranges (v4 — simplified check)
_CF_RANGES: List[str] = [
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.",
    "108.162.", "131.0.72.", "141.101.", "162.158.", "172.64.",
    "172.65.", "172.66.", "172.67.", "173.245.", "188.114.",
    "190.93.", "197.234.", "198.41.",
]


def _is_cloudflare(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _CF_RANGES)


class SubdomainEnum:
    """Subdomain enumerator — bruteforce + crt.sh + CF detection."""

    def __init__(self, domain: str, threads: int = 100) -> None:
        self.domain: str = domain
        self.threads: int = threads
        self.found: Dict[str, Dict[str, str]] = {}  # sub -> {ip, cf}
        self._main_ip: str = ""
        try:
            self._main_ip = socket.gethostbyname(domain)
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _resolve(self, subdomain: str) -> Optional[Tuple[str, str]]:
        """Resolve a single subdomain, return (fqdn, ip) or None."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except socket.gaierror:
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    def bruteforce(self) -> Dict[str, Dict[str, str]]:
        """Threaded bruteforce resolution of common subdomains."""
        print(f"\n  🔍 Bruteforcing {len(TOP_SUBDOMAINS)} subdomains for {self.domain}")
        results: Dict[str, Dict[str, str]] = {}
        done = 0
        total = len(TOP_SUBDOMAINS)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._resolve, s): s for s in TOP_SUBDOMAINS}
            for future in as_completed(futures):
                done += 1
                if done % 50 == 0 or done == total:
                    pct = (done / total) * 100
                    sys.stdout.write(f"\r  [{done}/{total}] {pct:.0f}%")
                    sys.stdout.flush()
                try:
                    result = future.result()
                    if result:
                        fqdn, ip = result
                        cf = "Yes" if _is_cloudflare(ip) else "No"
                        results[fqdn] = {"ip": ip, "cloudflare": cf}
                        sys.stdout.write(f"\r  ✓ {fqdn:<45} {ip:<18} CF: {cf}\n")
                        sys.stdout.flush()
                except Exception:
                    pass

        print(f"\n  Bruteforce found {len(results)} subdomains")
        return results

    # ------------------------------------------------------------------
    def from_crt_sh(self) -> Dict[str, Dict[str, str]]:
        """Query crt.sh certificate transparency logs."""
        print(f"\n  🔍 Querying crt.sh for {self.domain}")
        results: Dict[str, Dict[str, str]] = {}
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            data = json.loads(resp.read().decode("utf-8"))

            subdomains: Set[str] = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{self.domain}") or line == self.domain:
                        line = line.lstrip("*.")
                        if line and not line.startswith("*"):
                            subdomains.add(line)

            print(f"  crt.sh returned {len(subdomains)} unique names")

            # Resolve them
            def _try_resolve(sub: str) -> Optional[Tuple[str, str]]:
                try:
                    ip = socket.gethostbyname(sub)
                    return (sub, ip)
                except Exception:
                    return None

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {pool.submit(_try_resolve, s): s for s in subdomains}
                for future in as_completed(futures):
                    try:
                        r = future.result()
                        if r:
                            fqdn, ip = r
                            cf = "Yes" if _is_cloudflare(ip) else "No"
                            results[fqdn] = {"ip": ip, "cloudflare": cf}
                    except Exception:
                        pass

            print(f"  crt.sh resolved {len(results)} subdomains")
        except Exception as e:
            print(f"  ⚠ crt.sh query failed: {e}")

        return results

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Dict[str, str]]:
        """Full enumeration: bruteforce + crt.sh, deduplicated."""
        print(f"\n  {'='*60}")
        print(f"  Subdomain Enumeration — {self.domain}")
        print(f"  Main IP: {self._main_ip or 'unresolved'}")
        print(f"  {'='*60}")

        start = time.time()

        brute_results = self.bruteforce()
        crt_results = self.from_crt_sh()

        # Merge
        self.found = {**brute_results, **crt_results}

        elapsed = time.time() - start
        self._print_report(elapsed)
        return self.found

    # ------------------------------------------------------------------
    def _print_report(self, elapsed: float) -> None:
        """Format final results."""
        print(f"\n  {'='*70}")
        print(f"  SUBDOMAIN ENUMERATION REPORT — {self.domain}")
        print(f"  Total found: {len(self.found)} | Time: {elapsed:.2f}s")
        print(f"  {'='*70}")
        print(f"  {'SUBDOMAIN':<45} {'IP':<18} {'CF':<5} {'SAME IP'}")
        print(f"  {'-'*45} {'-'*18} {'-'*5} {'-'*8}")

        for sub in sorted(self.found.keys()):
            info = self.found[sub]
            same = "Yes" if info["ip"] == self._main_ip else "No"
            print(f"  {sub:<45} {info['ip']:<18} {info['cloudflare']:<5} {same}")

        cf_count = sum(1 for v in self.found.values() if v["cloudflare"] == "Yes")
        diff_ip = sum(1 for v in self.found.values() if v["ip"] != self._main_ip)
        print(f"\n  Behind Cloudflare: {cf_count}")
        print(f"  Different IP from main: {diff_ip}")
        print(f"  {'='*70}\n")
