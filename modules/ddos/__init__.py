"""
HYDRA STORM v7.0 — DDoS Module Package
All attack vectors, one import away.
"""

from hydra_storm.modules.ddos.http_flood import (
    HTTPKeepAliveFlood,
    HTTPProxyFlood,
    HTTP2Flood,
    build_request_pool,
)
from hydra_storm.modules.ddos.udp_flood import (
    UDPCannon,
    DNSAmplification,
    NTPAmplification,
    SSDPAmplification,
    discover_reflectors,
)
from hydra_storm.modules.ddos.tcp_flood import (
    TCPHammer,
    SYNFlood,
    ACKFlood,
    RSTFlood,
)
from hydra_storm.modules.ddos.slowloris import (
    SlowlorisAttack,
    RUDYAttack,
    SlowReadAttack,
)
from hydra_storm.modules.ddos.websocket_flood import (
    WSFlood,
)
from hydra_storm.modules.ddos.engine import (
    SharedMetrics,
    AttackConfig,
    worker_process,
    launch_attack,
)

__all__ = [
    # HTTP
    "HTTPKeepAliveFlood", "HTTPProxyFlood", "HTTP2Flood", "build_request_pool",
    # UDP
    "UDPCannon", "DNSAmplification", "NTPAmplification", "SSDPAmplification",
    "discover_reflectors",
    # TCP
    "TCPHammer", "SYNFlood", "ACKFlood", "RSTFlood",
    # Slow
    "SlowlorisAttack", "RUDYAttack", "SlowReadAttack",
    # WebSocket
    "WSFlood",
    # Engine
    "SharedMetrics", "AttackConfig", "worker_process", "launch_attack",
]
