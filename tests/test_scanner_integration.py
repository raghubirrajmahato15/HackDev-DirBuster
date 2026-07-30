"""
End-to-end tests against the real local server in conftest.py - proves
soft-404 detection, tech-aware wordlist merging, recursion, and adaptive
throttling backoff all actually work, not just against mocks.
"""
from __future__ import annotations

from hackdev_dirbuster.scanner import scan
from hackdev_dirbuster.wordlists import DEFAULT_STATUS_CODES


WORDLIST = ["admin", "realdir", "throttle", "nonexistent-path-one", "nonexistent-path-two"]


def test_scan_finds_real_hits_and_filters_soft_404(dirbuster_server):
    results, stats, tech = scan(
        base_url=dirbuster_server,
        words=WORDLIST,
        threads=5,
        timeout=5.0,
        rate=0,
        status_codes=set(DEFAULT_STATUS_CODES),
        follow_redirects=False,
        max_depth=1,
    )

    assert stats.soft_404_detected is True
    paths_found = {r.path for r in results}

    # Genuine hits survive.
    assert "admin" in paths_found
    assert "realdir" in paths_found
    # Soft-404 wildcard paths are filtered out entirely.
    assert "nonexistent-path-one" not in paths_found
    assert "nonexistent-path-two" not in paths_found


def test_scan_detects_redirect_as_directory_and_recurses(dirbuster_server):
    results, stats, tech = scan(
        base_url=dirbuster_server,
        words=WORDLIST,
        threads=5,
        timeout=5.0,
        rate=0,
        status_codes=set(DEFAULT_STATUS_CODES),
        follow_redirects=False,
        max_depth=2,
    )
    realdir_hit = next(r for r in results if r.path == "realdir")
    assert realdir_hit.is_directory is True
    assert stats.directories_recursed >= 1
    assert stats.max_depth_reached >= 1


def test_scan_detects_wordpress_tech_signal(dirbuster_server):
    results, stats, tech = scan(
        base_url=dirbuster_server,
        words=["admin"],
        threads=2,
        timeout=5.0,
        rate=0,
        status_codes=set(DEFAULT_STATUS_CODES),
        follow_redirects=False,
        max_depth=0,
        no_tech_detect=False,
    )
    assert "wordpress" in tech.technologies
    assert stats.tech_detected == ["wordpress"]


def test_scan_no_tech_detect_flag_skips_fingerprinting(dirbuster_server):
    results, stats, tech = scan(
        base_url=dirbuster_server,
        words=["admin"],
        threads=2,
        timeout=5.0,
        rate=0,
        status_codes=set(DEFAULT_STATUS_CODES),
        follow_redirects=False,
        max_depth=0,
        no_tech_detect=True,
    )
    assert tech.technologies == set()
    assert stats.tech_detected == []


def test_scan_recovers_from_throttling(dirbuster_server):
    results, stats, tech = scan(
        base_url=dirbuster_server,
        words=["throttle"],
        threads=1,
        timeout=5.0,
        rate=0,
        status_codes=set(DEFAULT_STATUS_CODES),
        follow_redirects=False,
        max_depth=0,
        no_tech_detect=True,
    )
    # The server 429s three times then succeeds; the adaptive controller's
    # internal retry-with-backoff should transparently recover and still
    # report the eventual 200.
    assert stats.throttle_events >= 1
    throttle_hit = next((r for r in results if r.path == "throttle"), None)
    assert throttle_hit is not None
    assert throttle_hit.status == 200
