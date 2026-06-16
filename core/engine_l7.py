import sys
import asyncio
import random
from typing import Dict, Any, List, Optional
import aiohttp
from core.colors import log_info, log_danger

# Dynamic UVLoop integration for Unix-based environments
if sys.platform != "win32":
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        log_info("High-Performance uvloop integration enabled.")
    except ImportError:
        pass

class L7Engine:
    """
    High-Performance asynchronous HTTP/L7 engine supporting connection pooling
    and dynamic proxy rotation.
    """
    def __init__(self, target: str, proxies: Optional[List[str]] = None, timeout: float = 5.0):
        self.target = target
        self.proxies = proxies or []
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.success_count = 0
        self.fail_count = 0

    def _get_random_proxy_url(self) -> Optional[str]:
        """Returns a random proxy from the list in proxy URI format."""
        if not self.proxies:
            return None
        proxy = random.choice(self.proxies)
        # Ensure it has schema
        if not proxy.startswith(("http://", "https://")):
            return f"http://{proxy}"
        return proxy

    async def send_request(self, session: aiohttp.ClientSession, method: str = "GET", headers: Optional[Dict[str, str]] = None) -> bool:
        """
        Send a single high-speed asynchronous request.
        Protects the core event loop from exceptions.
        """
        proxy_url = self._get_random_proxy_url()
        try:
            async with session.request(
                method=method,
                url=self.target,
                headers=headers,
                proxy=proxy_url,
                timeout=self.timeout,
                allow_redirects=False
            ) as response:
                if response.status < 400:
                    self.success_count += 1
                    return True
                else:
                    self.fail_count += 1
                    return False
        except Exception:
            self.fail_count += 1
            return False

    async def run_stress_test(
        self,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        duration: int = 60,
        concurrency: int = 200,
        rate_tracker = None
    ):
        """
        High-throughput connection pool runner.
        :param rate_tracker: Optional callback or object to update live RPS.
        """
        end_time = asyncio.get_event_loop().time() + duration
        
        # Performance optimized TCPConnector settings
        connector = aiohttp.TCPConnector(
            limit=0, # Unlimited simultaneous connections, bounded by semaphore
            ttl_dns_cache=300,
            ssl=False, # Disable SSL handshake validation overhead
            use_dns_cache=True
        )

        async with aiohttp.ClientSession(connector=connector) as session:
            sem = asyncio.Semaphore(concurrency)

            async def worker():
                while asyncio.get_event_loop().time() < end_time:
                    async with sem:
                        res = await self.send_request(session, method=method, headers=headers)
                        if rate_tracker and res:
                            rate_tracker(1)

            # Spawn concurrent tasks
            tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
            await asyncio.gather(*tasks, return_exceptions=True)
