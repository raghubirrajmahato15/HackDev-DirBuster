#!/usr/bin/env python3
"""
HackDev-DirBuster
==================

Concurrent, recursive, tech-aware directory and file brute-forcer with
adaptive concurrency/backoff and response-fingerprint deduplication.

Thin CLI entrypoint - the actual implementation lives in the
hackdev_dirbuster/ package (scanner.py, fingerprint.py, wordlists.py, cli.py).

For authorized security testing only. See README.md for legal notice.
"""
import sys

from hackdev_dirbuster.cli import main

if __name__ == "__main__":
    sys.exit(main())
