"""Command-line interface for HackDev-DirBuster."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from . import __version__
from .scanner import scan
from .wordlists import (
    DEFAULT_STATUS_CODES,
    build_wordlist,
    load_wordlist,
    parse_extensions,
    parse_status_codes,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hackdev-dirbuster",
        description="Concurrent, recursive, tech-aware directory/file brute-forcer.",
    )
    parser.add_argument("url", help="Base target URL (e.g. https://example.com/)")
    parser.add_argument("--wordlist", metavar="PATH", help="Path to a custom wordlist file")
    parser.add_argument("--extensions", metavar="php,html,js", default="", help="Comma-separated extensions to fan out over each word")
    parser.add_argument("--status-codes", metavar="200,301,403", help=f"Comma-separated interesting status codes (default: {sorted(DEFAULT_STATUS_CODES)})")
    parser.add_argument("--max-depth", type=int, default=2, help="Max recursion depth into discovered directories (default: 2)")
    parser.add_argument("--no-tech-detect", action="store_true", help="Disable tech-stack fingerprinting and wordlist augmentation")
    parser.add_argument("--dedup-threshold", type=int, default=3, help="Collapse >= N identical-fingerprint hits into one (default: 3)")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects (off by default)")
    parser.add_argument("-o", "--output", help="Write results to this file instead of stdout")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--threads", type=int, default=20, help="Max concurrent requests (default: 20)")
    parser.add_argument("--min-threads", type=int, default=2, help="Floor for adaptive backoff (default: 2)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--rate", type=float, default=0.0, help="Max requests per second, 0 = unlimited (default: 0)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def format_text(results, stats, tech) -> str:
    lines = []
    if tech.technologies:
        lines.append(f"Tech detected: {', '.join(sorted(tech.technologies))}")
    if stats.soft_404_detected:
        lines.append(f"Soft-404 baseline: status={stats.baseline_status} length={stats.baseline_length}")
    lines.append("")
    lines.append(f"{'STATUS':<8}{'LENGTH':<10}{'DEPTH':<7}{'PATH'}")
    for r in results:
        marker = " [likely-false-positive x%d]" % r.duplicate_count if r.likely_false_positive else ""
        lines.append(f"{r.status:<8}{r.length:<10}{r.depth:<7}{r.path}{marker}")
    lines.append("")
    lines.append(
        f"{stats.total_tried} tried, {stats.total_interesting} interesting, "
        f"{stats.dedup_collapsed} collapsed as false positives, "
        f"{stats.throttle_events} throttle event(s), {stats.duration_seconds:.2f}s"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    words = load_wordlist(args.wordlist)
    extensions = parse_extensions(args.extensions)
    words = build_wordlist(words, extensions)
    status_codes = parse_status_codes(args.status_codes)

    start = time.monotonic()
    try:
        results, stats, tech = scan(
            base_url=args.url,
            words=words,
            threads=args.threads,
            timeout=args.timeout,
            rate=args.rate,
            status_codes=status_codes,
            follow_redirects=args.follow_redirects,
            max_depth=args.max_depth,
            no_tech_detect=args.no_tech_detect,
            dedup_threshold=args.dedup_threshold,
            min_threads=args.min_threads,
        )
    except KeyboardInterrupt:
        logging.warning("Scan interrupted by user")
        return 130

    if args.format == "json":
        output = json.dumps(
            {"results": [r.to_dict() for r in results], "stats": stats.to_dict(), "tech": tech.to_dict()},
            indent=2,
        )
    else:
        output = format_text(results, stats, tech)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        print(f"Results written to {args.output}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
