import asyncio
import aiohttp
import time
from core.colors import log_info, log_success, log_warning, log_danger

class ScannerModule:
    def __init__(self):
        self.ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    async def scan_port(self, target, port):
        try:
            # Setting a very short timeout for high-speed scanning
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=0.5)
            log_success(f"[OPEN] Port {port} is open on {target}")
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def run_fast_scan(self, target):
        log_info(f"Starting High-Speed Port Scan on {target}...")
        tasks = [self.scan_port(target, port) for port in self.ports_to_scan]
        await asyncio.gather(*tasks)
        log_info("Port Scan Finished.")

    def run(self, target):
        asyncio.run(self.run_fast_scan(target))
