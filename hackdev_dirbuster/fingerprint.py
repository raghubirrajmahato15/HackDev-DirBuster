"""
Tech-stack-aware fingerprinting.

Fetches the target's base URL exactly once and inspects the response
headers and body for signals that identify common web frameworks/CMSes
(WordPress, Django, Laravel, Express). Detected technologies are used by
the caller to merge in a small built-in tech-specific path list, unless
``--no-tech-detect`` is passed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    import httpx


@dataclass
class TechDetectionResult:
    """The outcome of fingerprinting a target's base URL."""

    technologies: set[str] = field(default_factory=set)
    signals: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "technologies": sorted(self.technologies),
            "signals": {tech: sigs for tech, sigs in self.signals.items()},
        }


def _record(result: TechDetectionResult, tech: str, signal: str) -> None:
    result.technologies.add(tech)
    result.signals.setdefault(tech, []).append(signal)


def analyze_response(headers: dict, body: str) -> TechDetectionResult:
    """Pure analysis of headers + body text, independent of any network I/O.

    Kept separate from ``detect_tech`` so the detection logic itself can be
    unit tested without spinning up a server or an HTTP client.
    """
    result = TechDetectionResult()

    # Normalize headers to a case-insensitive-friendly lookup.
    lower_headers = {k.lower(): v for k, v in headers.items()}
    x_powered_by = lower_headers.get("x-powered-by", "")
    server = lower_headers.get("server", "")
    set_cookie = lower_headers.get("set-cookie", "")

    body_lower = body.lower()

    # --- WordPress -------------------------------------------------------
    if "wp-content" in body_lower:
        _record(result, "wordpress", "body contains 'wp-content'")
    if "wp-includes" in body_lower:
        _record(result, "wordpress", "body contains 'wp-includes'")
    if "wp-login.php" in body_lower:
        _record(result, "wordpress", "body links to 'wp-login.php'")
    generator_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE
    )
    generator = generator_match.group(1) if generator_match else ""
    if "wordpress" in generator.lower():
        _record(result, "wordpress", f"generator meta tag: {generator}")

    # --- Django ------------------------------------------------------------
    if "csrfmiddlewaretoken" in body_lower:
        _record(result, "django", "body contains 'csrfmiddlewaretoken'")
    if "wsgiserver" in server.lower():
        _record(result, "django", f"Server header: {server}")
    if "csrftoken" in set_cookie.lower():
        _record(result, "django", "Set-Cookie contains 'csrftoken'")
    if "django" in generator.lower():
        _record(result, "django", f"generator meta tag: {generator}")

    # --- Laravel -------------------------------------------------------
    if "laravel_session" in set_cookie.lower():
        _record(result, "laravel", "Set-Cookie contains 'laravel_session'")
    if "laravel" in body_lower:
        _record(result, "laravel", "body mentions 'Laravel'")
    if "laravel" in generator.lower():
        _record(result, "laravel", f"generator meta tag: {generator}")
    if "x-xsrf-token" in body_lower or "xsrf-token" in set_cookie.lower():
        _record(result, "laravel", "XSRF-TOKEN cookie/meta present")

    # --- Express / Node.js -----------------------------------------------
    if "express" in x_powered_by.lower():
        _record(result, "express", f"X-Powered-By header: {x_powered_by}")

    return result


def detect_tech(client: "httpx.Client", base_url: str, timeout: float) -> TechDetectionResult:
    """Fetch the base URL exactly once and fingerprint the tech stack from it.

    Network/HTTP errors are swallowed: fingerprinting is a best-effort
    enhancement and must never abort the scan.
    """
    try:
        response = client.get(base_url, timeout=timeout, follow_redirects=True)
    except Exception as exc:  # noqa: BLE001 - fingerprinting must not crash the scan
        logging.warning("Tech fingerprint probe failed: %s", exc)
        return TechDetectionResult()

    body = response.text if response.content else ""
    result = analyze_response(dict(response.headers), body)

    if result.technologies:
        logging.info(
            "Tech fingerprint detected: %s",
            ", ".join(sorted(result.technologies)),
        )
        for tech, sigs in result.signals.items():
            for sig in sigs:
                logging.debug("  [%s] signal: %s", tech, sig)
    else:
        logging.info("Tech fingerprint: no known tech stack signals detected")

    return result
