"""
Hydra Storm v7.0 — Wordlist Downloader & Manager
==================================================
Downloads popular wordlists from GitHub (SecLists etc.),
manages local storage, and loads them into memory.
"""

import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ---------------------------------------------------------------------------
# Default wordlist sources (raw GitHub URLs)
# ---------------------------------------------------------------------------
WORDLIST_URLS: Dict[str, str] = {
    # --- credentials ---
    "rockyou-top1000": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
    ),
    "rockyou-top10000": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
    ),
    "rockyou-top100000": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/Common-Credentials/10-million-password-list-top-100000.txt"
    ),
    "default-creds": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/Default-Credentials/default-passwords.csv"
    ),
    "darkweb-top10000": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/darkweb2017-top10000.txt"
    ),
    # --- usernames ---
    "usernames-top": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Usernames/top-usernames-shortlist.txt"
    ),
    "usernames-names": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Usernames/Names/names.txt"
    ),
    # --- web discovery ---
    "dirs-common": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/common.txt"
    ),
    "dirs-big": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/big.txt"
    ),
    "dirs-raft-large": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/raft-large-directories.txt"
    ),
    "dirs-raft-large-files": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/raft-large-files.txt"
    ),
    # --- subdomains ---
    "subdomains-top5000": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/DNS/subdomains-top1million-5000.txt"
    ),
    "subdomains-top20000": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/DNS/subdomains-top1million-20000.txt"
    ),
    "subdomains-top110000": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/DNS/subdomains-top1million-110000.txt"
    ),
    # --- fuzzing ---
    "sqli-generic": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Fuzzing/SQLi/Generic-SQLi.txt"
    ),
    "xss-cheatsheet": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt"
    ),
    "lfi-linux": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Fuzzing/LFI/LFI-Jhaddix.txt"
    ),
}


# ---------------------------------------------------------------------------
# WordlistManager
# ---------------------------------------------------------------------------
class WordlistManager:
    """Download, store, and load wordlists for Hydra Storm."""

    def __init__(self, base_dir: Optional[str] = None) -> None:
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path(__file__).resolve().parent / "data"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    # -- download -----------------------------------------------------------

    def download(
        self,
        name: str,
        dest_path: Optional[str] = None,
        chunk_size: int = 8192,
    ) -> Path:
        """
        Download a wordlist by name.

        Args:
            name:      key in WORDLIST_URLS
            dest_path: override destination file path
            chunk_size: bytes per read chunk

        Returns:
            Path to the downloaded file.
        """
        url = WORDLIST_URLS.get(name)
        if url is None:
            raise KeyError(
                f"Unknown wordlist '{name}'. Available: {list(WORDLIST_URLS)}"
            )

        if dest_path:
            dest = Path(dest_path)
        else:
            ext = url.rsplit(".", 1)[-1] if "." in url.split("/")[-1] else "txt"
            dest = self.base_dir / f"{name}.{ext}"

        dest.parent.mkdir(parents=True, exist_ok=True)

        print(f"  [↓] Downloading {name}")
        print(f"      URL : {url}")
        print(f"      Dest: {dest}")

        req = Request(url, headers={"User-Agent": "HydraStorm/7.0"})

        try:
            resp = urlopen(req, timeout=30)
            total = resp.headers.get("Content-Length")
            total_bytes = int(total) if total else None

            downloaded = 0
            hasher = hashlib.sha256()

            with open(dest, "wb") as fh:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    fh.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    self._progress(downloaded, total_bytes, name)

            print()  # newline after progress bar
            print(f"      Size: {downloaded:,} bytes")
            print(f"      SHA2: {hasher.hexdigest()[:16]}...")
            print(f"  [✓] {name} saved\n")
            return dest

        except HTTPError as exc:
            print(f"\n  [!] HTTP {exc.code} downloading {name}: {exc.reason}")
            raise
        except URLError as exc:
            print(f"\n  [!] Network error downloading {name}: {exc.reason}")
            raise
        except OSError as exc:
            print(f"\n  [!] IO error: {exc}")
            raise

    def download_all(self) -> Dict[str, Path]:
        """Download every wordlist in WORDLIST_URLS."""
        results: Dict[str, Path] = {}
        total = len(WORDLIST_URLS)
        print(f"\n{'='*60}")
        print(f"  Downloading {total} wordlists to {self.base_dir}")
        print(f"{'='*60}\n")

        for idx, name in enumerate(WORDLIST_URLS, 1):
            print(f"  [{idx}/{total}]", end=" ")
            try:
                path = self.download(name)
                results[name] = path
            except Exception as exc:
                print(f"  [!] Failed: {name} — {exc}\n")

        ok = len(results)
        fail = total - ok
        print(f"\n  Done: {ok} downloaded, {fail} failed.\n")
        return results

    # -- load ---------------------------------------------------------------

    def load(self, name_or_path: str) -> List[str]:
        """
        Load a wordlist into memory.

        Args:
            name_or_path: either a WORDLIST_URLS key or a file path.

        Returns:
            List of stripped, non-empty lines.
        """
        path = Path(name_or_path)

        # if it's a name, resolve to local file
        if not path.exists():
            # try matching a downloaded file
            candidates = list(self.base_dir.glob(f"{name_or_path}.*"))
            if candidates:
                path = candidates[0]
            else:
                raise FileNotFoundError(
                    f"Wordlist '{name_or_path}' not found locally. "
                    f"Download it first with download('{name_or_path}')."
                )

        lines: List[str] = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith("#"):
                    lines.append(line)

        print(f"  [✓] Loaded {len(lines):,} entries from {path.name}")
        return lines

    # -- listing ------------------------------------------------------------

    def list_available(self) -> None:
        """Print available wordlists (local + downloadable)."""
        print(f"\n{'='*60}")
        print(f"  WORDLIST INVENTORY")
        print(f"{'='*60}")

        # local files
        local_files = sorted(self.base_dir.glob("*"))
        local_names = {f.stem for f in local_files if f.is_file()}

        print(f"\n  {'Name':<30} {'Status':<12} {'Size':>12}")
        print(f"  {'─'*30} {'─'*12} {'─'*12}")

        for name in sorted(WORDLIST_URLS):
            candidates = list(self.base_dir.glob(f"{name}.*"))
            if candidates:
                f = candidates[0]
                size = f.stat().st_size
                size_str = self._fmt_size(size)
                print(f"  {name:<30} {'LOCAL':<12} {size_str:>12}")
            else:
                print(f"  {name:<30} {'REMOTE':<12} {'—':>12}")

        # any extra local files not in the registry
        extras = {f.stem for f in local_files if f.is_file()} - set(WORDLIST_URLS)
        if extras:
            print(f"\n  Extra local files:")
            for stem in sorted(extras):
                candidates = list(self.base_dir.glob(f"{stem}.*"))
                if candidates:
                    f = candidates[0]
                    size_str = self._fmt_size(f.stat().st_size)
                    print(f"  {stem:<30} {'LOCAL':<12} {size_str:>12}")

        print(f"{'='*60}\n")

    # -- progress display ---------------------------------------------------

    @staticmethod
    def _progress(current: int, total: Optional[int], name: str) -> None:
        if total:
            pct = current / total * 100
            bar_len = 30
            filled = int(bar_len * current / total)
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(f"\r      [{bar}] {pct:5.1f}%  {current:,}/{total:,} bytes")
        else:
            sys.stdout.write(f"\r      {current:,} bytes downloaded...")
        sys.stdout.flush()

    @staticmethod
    def _fmt_size(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
            n /= 1024  # type: ignore[assignment]
        return f"{n:.1f} TB"
