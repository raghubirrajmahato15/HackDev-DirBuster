"""
Core scanning engine.

Implements:
  * Concurrent brute-forcing over a wordlist via ThreadPoolExecutor + httpx
  * Soft-404 baseline detection (single random-path probe)
  * Response-fingerprint deduplication (collapses many identical "interesting"
    hits that are actually soft-404 variants the baseline probe alone missed)
  * Recursive brute-forcing into discovered directories, up to --max-depth
  * Adaptive concurrency/backoff that reacts to 429/503 responses and ramps
    back up once the target stabilizes
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
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

from .fingerprint import TechDetectionResult, detect_tech
from .wordlists import DEFAULT_USER_AGENT, merge_tech_wordlist

# Status codes that indicate the target (or an intermediary) is throttling us.
THROTTLE_STATUS_CODES: set[int] = {429, 503}

# Redirect status codes.
REDIRECT_STATUS_CODES: set[int] = {301, 302, 303, 307, 308}


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------
@dataclass
class ScanResult:
    """A single structured result for one probed URL."""

    url: str
    path: str
    status: int
    length: int
    redirect_to: Optional[str] = None
    content_type: str = ""
    depth: int = 0
    body_hash: Optional[str] = None
    is_directory: bool = False
    likely_false_positive: bool = False
    duplicate_count: int = 1

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": self.path,
            "status": self.status,
            "length": self.length,
            "redirect_to": self.redirect_to,
            "content_type": self.content_type,
            "depth": self.depth,
            "is_directory": self.is_directory,
            "likely_false_positive": self.likely_false_positive,
            "duplicate_count": self.duplicate_count,
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
    tech_detected: list[str] = field(default_factory=list)
    directories_recursed: int = 0
    max_depth_reached: int = 0
    dedup_collapsed: int = 0
    throttle_events: int = 0
    final_concurrency: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "total_tried": self.total_tried,
            "total_interesting": self.total_interesting,
            "total_errors": self.total_errors,
            "duration_seconds": round(self.duration_seconds, 3),
            "soft_404_detected": self.soft_404_detected,
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
            "tech_detected": self.tech_detected,
            "directories_recursed": self.directories_recursed,
            "max_depth_reached": self.max_depth_reached,
            "dedup_collapsed": self.dedup_collapsed,
            "throttle_events": self.throttle_events,
            "final_concurrency": self.final_concurrency,
        }


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# Adaptive concurrency / backoff controller
# --------------------------------------------------------------------------
class AdaptiveController:
    """
    Gates concurrent in-flight requests through a dynamically resizable
    limit. When the target starts returning 429/503, the limit is halved
    and a per-request delay is introduced. After a streak of clean
    responses, the limit ramps back up towards the original ceiling and
    the delay decays.
    """

    def __init__(self, max_workers: int, min_workers: int = 1, ramp_streak: int = 12) -> None:
        self.max_workers = max(1, max_workers)
        self.min_workers = max(1, min_workers)
        self.ramp_streak = ramp_streak
        self.current_limit = self.max_workers
        self.active = 0
        self.delay = 0.0
        self.success_streak = 0
        self.throttle_events = 0
        self._cond = threading.Condition()

    def acquire(self) -> None:
        with self._cond:
            while self.active >= self.current_limit:
                self._cond.wait()
            self.active += 1
            delay = self.delay
        if delay > 0:
            time.sleep(delay)

    def release(self) -> None:
        with self._cond:
            self.active -= 1
            self._cond.notify_all()

    def report_throttled(self) -> None:
        with self._cond:
            old_limit = self.current_limit
            old_delay = self.delay
            self.current_limit = max(self.min_workers, self.current_limit // 2 or self.min_workers)
            self.delay = min(5.0, old_delay * 2 if old_delay > 0 else 0.5)
            self.success_streak = 0
            self.throttle_events += 1
            self._cond.notify_all()
        if self.current_limit != old_limit or self.delay != old_delay:
            logging.warning(
                "Throttling detected (429/503): reducing concurrency %d -> %d, "
                "adding delay %.2fs -> %.2fs per request",
                old_limit, self.current_limit, old_delay, self.delay,
            )

    def report_success(self) -> None:
        ramp = False
        new_limit = self.current_limit
        new_delay = self.delay
        with self._cond:
            self.success_streak += 1
            if self.success_streak >= self.ramp_streak and self.current_limit < self.max_workers:
                self.current_limit = min(self.max_workers, self.current_limit + 1)
                self.success_streak = 0
                if self.delay > 0:
                    self.delay = max(0.0, self.delay - 0.25)
                new_limit = self.current_limit
                new_delay = self.delay
                ramp = True
            self._cond.notify_all()
        if ramp:
            logging.info(
                "Target stabilized: ramping concurrency back up to %d (delay=%.2fs)",
                new_limit, new_delay,
            )


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------
def random_path(length: int = 12) -> str:
    """Generate a random alphanumeric path segment unlikely to exist on the target."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


@dataclass
class RequestOutcome:
    status: Optional[int]
    length: int
    redirect_to: Optional[str]
    content_type: str
    body_text: str
    retry_after: Optional[float]
    error: Optional[BaseException]


def _perform_request(
    client: "httpx.Client",
    url: str,
    timeout: float,
    follow_redirects: bool,
) -> RequestOutcome:
    """Issue a single GET request and return a structured RequestOutcome."""
    try:
        response = client.get(url, timeout=timeout, follow_redirects=follow_redirects)
        redirect_to = None
        if response.status_code in REDIRECT_STATUS_CODES:
            redirect_to = response.headers.get("Location")
        content_type = response.headers.get("content-type", "").split(";")[0].strip()
        retry_after = None
        raw_retry_after = response.headers.get("Retry-After")
        if raw_retry_after:
            try:
                retry_after = float(raw_retry_after)
            except ValueError:
                retry_after = None
        body_text = ""
        if response.content:
            try:
                body_text = response.text
            except Exception:  # noqa: BLE001 - non-text bodies are fine to skip
                body_text = ""
        return RequestOutcome(
            status=response.status_code,
            length=len(response.content),
            redirect_to=redirect_to,
            content_type=content_type,
            body_text=body_text,
            retry_after=retry_after,
            error=None,
        )
    except httpx.HTTPError as exc:
        return RequestOutcome(
            status=None, length=0, redirect_to=None, content_type="", body_text="", retry_after=None, error=exc,
        )


def _request_with_backoff(
    client: "httpx.Client",
    url: str,
    timeout: float,
    follow_redirects: bool,
    controller: AdaptiveController,
    limiter: RateLimiter,
    max_retries: int = 4,
) -> RequestOutcome:
    """Perform a request, transparently retrying (with adaptive backoff) on 429/503."""
    attempt = 0
    while True:
        limiter.acquire()
        controller.acquire()
        try:
            outcome = _perform_request(client, url, timeout, follow_redirects)
        finally:
            controller.release()

        if outcome.error is not None:
            return outcome

        if outcome.status in THROTTLE_STATUS_CODES and attempt < max_retries:
            controller.report_throttled()
            wait = outcome.retry_after if outcome.retry_after is not None else max(controller.delay, 0.2)
            logging.debug("Got %s for %s, backing off %.2fs (attempt %d)", outcome.status, url, wait, attempt + 1)
            time.sleep(wait)
            attempt += 1
            continue

        controller.report_success()
        return outcome


# --------------------------------------------------------------------------
# Soft-404 baseline detection
# --------------------------------------------------------------------------
def detect_soft_404(
    client: "httpx.Client", base_url: str, timeout: float, follow_redirects: bool
) -> tuple[Optional[int], int]:
    """
    Probe a random, near-certainly-nonexistent path to establish a baseline for
    "soft 404" behavior (servers that return 200 with a generic error page instead
    of a real 404 status).
    """
    probe_path = f"{random_path()}-{random_path(6)}"
    outcome = _perform_request(client, urljoin(base_url, probe_path), timeout, follow_redirects)
    if outcome.error is not None:
        logging.warning("Soft-404 baseline probe failed: %s", outcome.error)
        return None, 0
    logging.info("Soft-404 baseline probe: %s -> status=%s length=%d", probe_path, outcome.status, outcome.length)
    return outcome.status, outcome.length


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


# --------------------------------------------------------------------------
# Response-fingerprint deduplication
# --------------------------------------------------------------------------
_DYNAMIC_TOKEN_RE = re.compile(r"\d+")
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_body(text: str) -> str:
    """
    Strip obviously dynamic bits (timestamps, counters, request IDs -- anything
    numeric) and collapse whitespace, so structurally-identical pages hash the
    same even if they embed a changing number somewhere.
    """
    if not text:
        return ""
    text = _DYNAMIC_TOKEN_RE.sub("#", text)
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


def compute_body_hash(text: str) -> str:
    """Hash the normalized body so structurally-identical responses collide."""
    normalized = normalize_body(text)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def dedupe_results(results: list[ScanResult], threshold: int = 3) -> tuple[list[ScanResult], int]:
    """
    Group "interesting" results by their response-body fingerprint. Any group
    of >= threshold results sharing an identical fingerprint is almost
    certainly a wildcard/soft-404 pattern that slipped past the single
    baseline probe (e.g. a catch-all route, or a WAF block page returned for
    many different paths) rather than genuinely distinct discoveries. Such
    groups are collapsed down to one representative entry flagged as a
    likely false positive, with a duplicate_count recording how many hits
    it stands in for.
    """
    groups: dict[str, list[ScanResult]] = {}
    for r in results:
        key = r.body_hash or f"__no_hash__:{r.url}"
        groups.setdefault(key, []).append(r)

    final: list[ScanResult] = []
    collapsed = 0
    for key, group in groups.items():
        if key.startswith("__no_hash__:") or len(group) < threshold:
            final.extend(group)
            continue
        representative = group[0]
        representative.likely_false_positive = True
        representative.duplicate_count = len(group)
        final.append(representative)
        collapsed += len(group) - 1

    final.sort(key=lambda r: r.status)
    return final, collapsed


# --------------------------------------------------------------------------
# Recursion helpers
# --------------------------------------------------------------------------
def _has_extension(path: str) -> bool:
    last_segment = path.rstrip("/").rsplit("/", 1)[-1]
    return "." in last_segment


def is_directory_like(status: int, redirect_to: Optional[str], content_type: str, path: str) -> bool:
    """
    Heuristic for "this discovered path looks like a directory worth
    recursing into": a redirect (typically bare-path -> trailing-slash), or
    a 200 response with an HTML/index-like content type and no file
    extension in the path.
    """
    if status in REDIRECT_STATUS_CODES:
        return True
    if status == 200 and not _has_extension(path):
        ctype = (content_type or "").lower()
        if "html" in ctype or ctype == "":
            return True
    return False


# --------------------------------------------------------------------------
# Core scan orchestration
# --------------------------------------------------------------------------
def _scan_single_level(
    client: "httpx.Client",
    base_url: str,
    words: list[str],
    depth: int,
    threads: int,
    timeout: float,
    follow_redirects: bool,
    status_codes: set[int],
    baseline_status: Optional[int],
    baseline_length: Optional[int],
    controller: AdaptiveController,
    limiter: RateLimiter,
    stats: ScanStats,
    stats_lock: threading.Lock,
) -> list[ScanResult]:
    """Brute-force `words` against `base_url` (one recursion level) and return hits."""
    level_results: list[ScanResult] = []

    def worker(path: str) -> Optional[ScanResult]:
        url = urljoin(base_url, path)
        outcome = _request_with_backoff(client, url, timeout, follow_redirects, controller, limiter)

        with stats_lock:
            stats.total_tried += 1

        if outcome.error is not None:
            with stats_lock:
                stats.total_errors += 1
            logging.debug("Request error for %s: %s", url, outcome.error)
            return None

        if outcome.status not in status_codes:
            return None

        if is_soft_404_match(outcome.status, outcome.length, baseline_status, baseline_length):
            logging.debug("Filtered soft-404 match: %s (status=%d length=%d)", url, outcome.status, outcome.length)
            return None

        directory = is_directory_like(outcome.status, outcome.redirect_to, outcome.content_type, path)
        return ScanResult(
            url=url,
            path=path,
            status=outcome.status,
            length=outcome.length,
            redirect_to=outcome.redirect_to,
            content_type=outcome.content_type,
            depth=depth,
            body_hash=compute_body_hash(outcome.body_text),
            is_directory=directory,
        )

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(worker, word): word for word in words}
        for future in as_completed(future_map):
            word = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - surfaced defensively, logged and counted
                with stats_lock:
                    stats.total_errors += 1
                logging.debug("Unexpected error scanning %s: %s", word, exc)
                continue
            if result is not None:
                level_results.append(result)
                with stats_lock:
                    stats.total_interesting += 1
                logging.info("[%d] %s (length=%d, depth=%d)", result.status, result.url, result.length, depth)

    return level_results


def scan(
    base_url: str,
    words: list[str],
    threads: int,
    timeout: float,
    rate: float,
    status_codes: set[int],
    follow_redirects: bool,
    max_depth: int = 2,
    no_tech_detect: bool = False,
    dedup_threshold: int = 3,
    min_threads: int = 2,
) -> tuple[list[ScanResult], ScanStats, TechDetectionResult]:
    """Run the concurrent, recursive, tech-aware brute-force scan."""
    if httpx is None:
        logging.error("The 'httpx' package is required to run scans. Install it with: pip install httpx")
        sys.exit(1)

    if not base_url.endswith("/"):
        base_url += "/"

    stats = ScanStats()
    stats_lock = threading.Lock()
    limiter = RateLimiter(rate)
    controller = AdaptiveController(max_workers=threads, min_workers=min_threads)

    headers = {"User-Agent": DEFAULT_USER_AGENT}
    start_time = time.monotonic()
    all_results: list[ScanResult] = []

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

        tech_result = TechDetectionResult()
        scan_words = words
        if not no_tech_detect:
            tech_result = detect_tech(client, base_url, timeout)
            if tech_result.technologies:
                scan_words = merge_tech_wordlist(words, tech_result.technologies)
                stats.tech_detected = sorted(tech_result.technologies)
                logging.info(
                    "Merged %d tech-specific paths into wordlist (now %d entries total)",
                    len(scan_words) - len(words),
                    len(scan_words),
                )

        logging.info("Starting scan of %s with %d paths using up to %d threads", base_url, len(scan_words), threads)

        # BFS across recursion depths.
        visited_dirs: set[str] = {base_url}
        queue: list[tuple[str, int]] = [(base_url, 0)]

        while queue:
            current_base, depth = queue.pop(0)
            level_results = _scan_single_level(
                client=client,
                base_url=current_base,
                words=scan_words,
                depth=depth,
                threads=threads,
                timeout=timeout,
                follow_redirects=follow_redirects,
                status_codes=status_codes,
                baseline_status=baseline_status,
                baseline_length=baseline_length,
                controller=controller,
                limiter=limiter,
                stats=stats,
                stats_lock=stats_lock,
            )
            all_results.extend(level_results)
            stats.max_depth_reached = max(stats.max_depth_reached, depth)

            if depth >= max_depth:
                continue

            for result in level_results:
                if not result.is_directory:
                    continue
                child_dir = result.path if result.path.endswith("/") else result.path + "/"
                child_url = urljoin(current_base, child_dir)
                if child_url in visited_dirs:
                    continue
                visited_dirs.add(child_url)
                stats.directories_recursed += 1
                queue.append((child_url, depth + 1))

    deduped, collapsed = dedupe_results(all_results, threshold=dedup_threshold)
    stats.dedup_collapsed = collapsed
    stats.duration_seconds = time.monotonic() - start_time
    stats.final_concurrency = controller.current_limit
    stats.throttle_events = controller.throttle_events

    return deduped, stats, tech_result
