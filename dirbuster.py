#!/usr/bin/env python3
"""
HackDev-DirBuster
==================

Concurrent directory and file brute-forcer with smart status-code filtering.

For authorized security testing only. See README.md for legal notice.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


# --------------------------------------------------------------------------
# Built-in default wordlist (~100 common paths)
# --------------------------------------------------------------------------
DEFAULT_WORDLIST: list[str] = [
    "admin", "administrator", "login", "logout", "backup", "backups", ".git",
    ".env", ".env.local", ".htaccess", ".htpasswd", "config", "config.php",
    "configuration", "api", "api/v1", "api/v2", "uploads", "upload", "images",
    "img", "css", "js", "assets", "static", "public", "private", "tmp", "temp",
    "test", "testing", "dev", "development", "staging", "prod", "production",
    "db", "database", "sql", "dump", "dump.sql", "backup.sql", "backup.zip",
    "backup.tar.gz", "www", "wwwroot", "html", "index", "home", "dashboard",
    "panel", "cpanel", "phpmyadmin", "adminer", "wp-admin", "wp-login.php",
    "wp-content", "wp-includes", "wp-config.php", "server-status", "status",
    "health", "healthz", "metrics", "debug", "swagger", "swagger.json",
    "swagger-ui", "docs", "documentation", "readme", "README.md", "changelog",
    "CHANGELOG.md", "license", "LICENSE", "robots.txt", "sitemap.xml",
    "favicon.ico", "crossdomain.xml", "web.config", "Dockerfile",
    "docker-compose.yml", "Makefile", "package.json", "composer.json",
    "requirements.txt", ".git/config", ".git/HEAD", ".svn", ".DS_Store",
    "id_rsa", "id_rsa.pub", "server.key", "server.crt", "secrets",
    "secret", "credentials", "auth", "authenticate", "register", "signup",
    "signin", "account", "accounts", "user", "users", "profile", "profiles",
    "settings", "setup", "install", "installer", "console", "shell",
    "cmd", "terminal", "phpinfo.php", "info.php", "test.php", "old",
    "old_site", "backup_old", "archive", "logs", "log", "error_log",
    "access_log", "cache", "vendor", "node_modules", "bin", "scripts",
    "includes", "inc", "lib", "libs", "data", "files", "file", "download",
    "downloads", "media", "video", "videos", "docs_internal", "internal",
    "management", "manage", "monitor", "monitoring", "graphql",
]

# Status codes considered "interesting" by default.
DEFAULT_STATUS_CODES: set[int] = {200, 204, 301, 302, 307, 401, 403}

# A conservative default User-Agent so scans aren't trivially blocked by UA sniffing.
DEFAULT_USER_AGENT = "HackDev-DirBuster/1.0 (+https://github.com/raghubirrajmahato15/HackDev-DirBuster)"


@dataclass
class ScanResult:
    """A single structured result for one probed URL."""

    url: str
    status: int
    length: int
    redirect_to: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "length": self.length,
            "redirect_to": self.redirect_to,
        }


@dataclass
class ScanStats:
    """Aggregate statistics for a full scan run."""

    total_tried: int = 0
    total_interesting: int = 0
    total_errors: int = 0
    duration_seconds: float = 0.0
    soft_404_detected: bool = False
    baseline_status: Optional[int] = None
    baseline_length: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "total_tried": self.total_tried,
            "total_interesting": self.total_interesting,
            "total_errors": self.total_errors,
            "duration_seconds": round(self.duration_seconds, 3),
            "soft_404_detected": self.soft_404_detected,
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
        }


class RateLimiter:
    """A simple thread-safe token-bucket-ish limiter capping requests/sec."""

    def __init__(self, rate: float) -> None:
        self.rate = rate  # requests per second, 0 = unlimited
        self._lock = threading.Lock()
        self._last_time = 0.0

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        min_interval = 1.0 / self.rate
        with self._lock:
            now = time.monotonic()
            wait = self._last_time + min_interval - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._last_time = now


def build_wordlist(base_words: list[str], extensions: list[str]) -> list[str]:
    """Expand a base wordlist with each extension appended, plus the raw entries."""
    expanded: list[str] = []
    seen: set[str] = set()

    def add(word: str) -> None:
        if word not in seen:
            seen.add(word)
            expanded.append(word)

    for word in base_words:
        add(word)
        if extensions and "." not in word.rsplit("/", 1)[-1]:
            for ext in extensions:
                ext = ext.strip().lstrip(".")
                if ext:
                    add(f"{word}.{ext}")
    return expanded


def load_wordlist(path: Optional[str]) -> list[str]:
    """Load a wordlist from disk, or fall back to the built-in default list."""
    if not path:
        logging.info("No --wordlist provided, using built-in default list (%d entries)", len(DEFAULT_WORDLIST))
        return list(DEFAULT_WORDLIST)

    words: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line)
    except OSError as exc:
        logging.error("Failed to read wordlist %s: %s", path, exc)
        sys.exit(1)

    if not words:
        logging.error("Wordlist %s is empty", path)
        sys.exit(1)

    logging.info("Loaded %d entries from wordlist %s", len(words), path)
    return words


def random_path(length: int = 12) -> str:
    """Generate a random alphanumeric path segment unlikely to exist on the target."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def _perform_request(
    client: "httpx.Client",
    base_url: str,
    path: str,
    timeout: float,
    follow_redirects: bool,
) -> tuple[Optional[int], int, Optional[str], Optional[Exception]]:
    """Issue a single GET request and return (status, length, redirect_to, error)."""
    url = urljoin(base_url, path)
    try:
        response = client.get(url, timeout=timeout, follow_redirects=follow_redirects)
        redirect_to = None
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_to = response.headers.get("Location")
        return response.status_code, len(response.content), redirect_to, None
    except httpx.HTTPError as exc:
        return None, 0, None, exc


def detect_soft_404(
    client: "httpx.Client", base_url: str, timeout: float, follow_redirects: bool
) -> tuple[Optional[int], int]:
    """
    Probe a random, near-certainly-nonexistent path to establish a baseline for
    "soft 404" behavior (servers that return 200 with a generic error page instead
    of a real 404 status).
    """
    probe_path = f"{random_path()}-{random_path(6)}"
    status, length, _, error = _perform_request(client, base_url, probe_path, timeout, follow_redirects)
    if error is not None:
        logging.warning("Soft-404 baseline probe failed: %s", error)
        return None, 0
    logging.info("Soft-404 baseline probe: %s -> status=%s length=%d", probe_path, status, length)
    return status, length


def is_soft_404_match(
    status: int, length: int, baseline_status: Optional[int], baseline_length: Optional[int], tolerance: int = 15
) -> bool:
    """Return True if this response looks like it's actually the soft-404 page."""
    if baseline_status is None:
        return False
    if status != baseline_status:
        return False
    if baseline_length == 0:
        return length == 0
    diff_ratio = abs(length - baseline_length) / max(baseline_length, 1)
    return diff_ratio <= (tolerance / 100.0)


def scan(
    base_url: str,
    words: list[str],
    threads: int,
    timeout: float,
    rate: float,
    status_codes: set[int],
    follow_redirects: bool,
) -> tuple[list[ScanResult], ScanStats]:
    """Run the concurrent brute-force scan and return results + stats."""
    if httpx is None:
        logging.error("The 'httpx' package is required to run scans. Install it with: pip install httpx")
        sys.exit(1)

    if not base_url.endswith("/"):
        base_url += "/"

    stats = ScanStats()
    results: list[ScanResult] = []
    limiter = RateLimiter(rate)
    lock = threading.Lock()

    headers = {"User-Agent": DEFAULT_USER_AGENT}
    start_time = time.monotonic()

    with httpx.Client(headers=headers) as client:
        baseline_status, baseline_length = detect_soft_404(client, base_url, timeout, follow_redirects)
        if baseline_status is not None and baseline_status in status_codes:
            stats.soft_404_detected = True
            logging.warning(
                "Soft-404 detected: baseline path returns status=%d length=%d. "
                "Matching responses will be filtered out of interesting results.",
                baseline_status,
                baseline_length,
            )
        stats.baseline_status = baseline_status
        stats.baseline_length = baseline_length

        def worker(path: str) -> Optional[ScanResult]:
            limiter.acquire()
            status, length, redirect_to, error = _perform_request(client, base_url, path, timeout, follow_redirects)
            with lock:
                stats.total_tried += 1
            if error is not None:
                with lock:
                    stats.total_errors += 1
                logging.debug("Request error for %s: %s", path, error)
                return None

            if status not in status_codes:
                return None

            if is_soft_404_match(status, length, baseline_status, baseline_length):
                logging.debug("Filtered soft-404 match: %s (status=%d length=%d)", path, status, length)
                return None

            return ScanResult(url=urljoin(base_url, path), status=status, length=length, redirect_to=redirect_to)

        logging.info("Starting scan of %s with %d paths using %d threads", base_url, len(words), threads)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {executor.submit(worker, word): word for word in words}
            for future in as_completed(future_map):
                word = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - surfaced defensively, logged and counted
                    with lock:
                        stats.total_errors += 1
                    logging.debug("Unexpected error scanning %s: %s", word, exc)
                    continue
                if result is not None:
                    with lock:
                        results.append(result)
                        stats.total_interesting += 1
                    logging.info("[%d] %s (length=%d)", result.status, result.url, result.length)

    stats.duration_seconds = time.monotonic() - start_time
    results.sort(key=lambda r: r.status)
    return results, stats


def format_text(results: list[ScanResult], stats: ScanStats) -> str:
    """Render results as a readable table, sorted by status code."""
    lines: list[str] = []
    if not results:
        lines.append("No interesting results found.")
    else:
        header = f"{'STATUS':<8}{'LENGTH':<10}{'URL':<60}{'REDIRECT':<30}"
        lines.append(header)
        lines.append("-" * len(header))
        for r in results:
            redirect = r.redirect_to or ""
            lines.append(f"{r.status:<8}{r.length:<10}{r.url:<60}{redirect:<30}")

    lines.append("")
    lines.append("Summary:")
    lines.append(f"  Total tried:        {stats.total_tried}")
    lines.append(f"  Total interesting:  {stats.total_interesting}")
    lines.append(f"  Total errors:       {stats.total_errors}")
    lines.append(f"  Duration (s):       {stats.duration_seconds:.2f}")
    if stats.soft_404_detected:
        lines.append(
            f"  Soft-404 detected:  yes (baseline status={stats.baseline_status}, "
            f"length={stats.baseline_length})"
        )
    return "\n".join(lines)


def format_json(results: list[ScanResult], stats: ScanStats) -> str:
    """Render results and stats as a JSON document."""
    payload = {
        "results": [r.to_dict() for r in results],
        "stats": stats.to_dict(),
    }
    return json.dumps(payload, indent=2)


def parse_status_codes(raw: Optional[str]) -> set[int]:
    """Parse a comma-separated list of status codes, falling back to the default set."""
    if not raw:
        return set(DEFAULT_STATUS_CODES)
    codes: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            codes.add(int(chunk))
        except ValueError:
            logging.error("Invalid status code in --status-codes: %r", chunk)
            sys.exit(1)
    if not codes:
        logging.error("--status-codes produced an empty set")
        sys.exit(1)
    return codes


def parse_extensions(raw: Optional[str]) -> list[str]:
    """Parse a comma-separated list of extensions."""
    if not raw:
        return []
    return [ext.strip().lstrip(".") for ext in raw.split(",") if ext.strip()]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dirbuster.py",
        description="HackDev-DirBuster: concurrent directory and file brute-forcer with smart status-code filtering.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Base target URL, e.g. https://example.com")
    parser.add_argument("--wordlist", default=None, help="Path to a wordlist file (one entry per line)")
    parser.add_argument(
        "--extensions",
        default=None,
        help='Comma-separated list of extensions to append to each entry, e.g. "php,html,js,txt,bak"',
    )
    parser.add_argument("-o", "--output", default=None, help="Write results to this file instead of stdout")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (debug) logging")
    parser.add_argument("--threads", type=int, default=20, help="Number of concurrent worker threads")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    parser.add_argument("--rate", type=float, default=0, help="Max requests per second across all threads (0=unlimited)")
    parser.add_argument(
        "--status-codes",
        default=None,
        help="Comma-separated list of status codes to treat as interesting (default: 200,204,301,302,307,401,403)",
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow HTTP redirects instead of recording them as-is (off by default)",
    )
    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)

    if not args.target.startswith(("http://", "https://")):
        logging.error("Target must start with http:// or https://")
        sys.exit(1)

    if args.threads <= 0:
        logging.error("--threads must be a positive integer")
        sys.exit(1)

    base_words = load_wordlist(args.wordlist)
    extensions = parse_extensions(args.extensions)
    words = build_wordlist(base_words, extensions)
    status_codes = parse_status_codes(args.status_codes)

    results, stats = scan(
        base_url=args.target,
        words=words,
        threads=args.threads,
        timeout=args.timeout,
        rate=args.rate,
        status_codes=status_codes,
        follow_redirects=args.follow_redirects,
    )

    output_text = format_json(results, stats) if args.format == "json" else format_text(results, stats)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output_text)
                fh.write("\n")
            logging.info("Results written to %s", args.output)
        except OSError as exc:
            logging.error("Failed to write output file %s: %s", args.output, exc)
            sys.exit(1)

    print(output_text)


if __name__ == "__main__":
    main()
