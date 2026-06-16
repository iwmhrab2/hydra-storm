import requests
import asyncio
import aiohttp
from core.colors import log_info, log_success, log_warning, log_danger

class DirBuster:
    def __init__(self, target, wordlist_file="wordlists/dirs_large.txt", threads=50):
        self.target = target if target.endswith('/') else target + '/'
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.found = []
        # Fallback small list if file not found
        self.words = ["admin", "login", "wp-admin", "backup", "api", "config", "db", "test", ".env", "phpmyadmin"]

    def load_words(self):
        try:
            with open(self.wordlist_file, 'r') as f:
                loaded = [line.strip() for line in f if line.strip()]
                if loaded:
                    self.words = loaded
        except FileNotFoundError:
            log_warning(f"Wordlist {self.wordlist_file} not found. Using small built-in list.")

    async def fetch(self, session, word):
        url = f"{self.target}{word}"
        try:
            async with session.get(url, allow_redirects=False) as response:
                if response.status in [200, 301, 302, 403]:
                    log_success(f"[/{word}] -> {response.status}")
                    self.found.append(url)
        except Exception:
            pass

    async def bound_fetch(self, sem, session, word):
        async with sem:
            await self.fetch(session, word)

    async def run_scan(self):
        self.load_words()
        log_info(f"Starting DirBuster on {self.target} with {len(self.words)} words...")
        sem = asyncio.Semaphore(self.threads)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            tasks = [asyncio.create_task(self.bound_fetch(sem, session, word)) for word in self.words]
            await asyncio.gather(*tasks)
        log_success(f"Directory Bruteforce complete. Found {len(self.found)} endpoints.")

    def run(self):
        asyncio.run(self.run_scan())
