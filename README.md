# HackDev-DirBuster

[![Test](https://github.com/raghubirrajmahato15/HackDev-DirBuster/actions/workflows/test.yml/badge.svg)](https://github.com/raghubirrajmahato15/HackDev-DirBuster/actions/workflows/test.yml)

Concurrent, recursive, tech-aware directory and file brute-forcer with adaptive concurrency/backoff
and response-fingerprint deduplication. Part of the [HackDev](https://github.com/raghubirrajmahato15)
open-source cybersecurity toolkit.

## Features

- Concurrent scanning via a `ThreadPoolExecutor`, sized with `--threads`
- Built-in default wordlist of ~100 common paths — no wordlist file required to get started
- `--wordlist` for your own list, `--extensions` to fan each entry out across file extensions
- **Automatic soft-404 detection**: probes a random nonexistent path first and filters real
  responses matching its status/length signature
- **Response-fingerprint deduplication**: any group of 3+ "interesting" hits sharing an identical
  normalized-body fingerprint (numbers stripped, whitespace collapsed) is collapsed into one
  representative entry flagged `likely_false_positive`, catching soft-404/WAF-block patterns the
  single baseline probe alone missed
- **Recursive brute-forcing**: directory-like discoveries (redirects, or 200 HTML responses with no
  file extension) are automatically re-scanned with the same wordlist, up to `--max-depth`
- **Tech-stack-aware wordlist augmentation**: fetches the base URL once, looks for WordPress/
  Django/Laravel/Express signals (headers, cookies, body content, generator meta tags), and merges
  in a small tech-specific path list automatically (disable with `--no-tech-detect`)
- **Adaptive concurrency/backoff**: 429/503 responses halve the concurrency limit and add a
  per-request delay; a streak of clean responses ramps concurrency back up and decays the delay
- Configurable "interesting" status codes via `--status-codes`
- Redirect handling: off by default (records `Location`), `--follow-redirects` to follow instead
- Rate limiting (`--rate`), per-request `--timeout`
- Text and JSON output (`--format`), file output via `-o/--output`

## Install

```bash
git clone https://github.com/raghubirrajmahato15/HackDev-DirBuster.git
cd HackDev-DirBuster
pip install -r requirements.txt
```

Requires Python 3.10+ and `httpx`.

## Usage examples

Scan a target using the built-in default wordlist (soft-404 detection, tech-aware wordlist merging,
and recursion up to depth 2 are all on by default):

```bash
python dirbuster.py https://example.com
```

Custom wordlist, extension fan-out, deeper recursion:

```bash
python dirbuster.py https://example.com --wordlist wordlists/common.txt --extensions php,html,js,txt,bak --max-depth 3
```

Tune concurrency and its adaptive floor, rate limit, and timeout:

```bash
python dirbuster.py https://example.com --threads 50 --min-threads 5 --rate 20 --timeout 5
```

Disable tech-stack fingerprinting and use a stricter dedup threshold, JSON output to a file:

```bash
python dirbuster.py https://example.com --no-tech-detect --dedup-threshold 2 --format json -o results.json
```

## CLI flag reference

| Flag | Default | Description |
|---|---|---|
| `url` (positional) | — | Base target URL, e.g. `https://example.com` |
| `--wordlist` | built-in ~100-entry list | Path to a custom wordlist file (one entry per line) |
| `--extensions` | none | Comma-separated extensions to append to each entry |
| `--status-codes` | `200,204,301,302,307,401,403` | Comma-separated "interesting" status codes |
| `--max-depth` | `2` | Max recursion depth into discovered directories |
| `--no-tech-detect` | off | Disable tech-stack fingerprinting and wordlist augmentation |
| `--dedup-threshold` | `3` | Collapse groups of >= N identical-fingerprint hits |
| `--follow-redirects` | off | Follow redirects instead of just recording `Location` |
| `-o`, `--output` | stdout | Write results to this file |
| `--format` | `text` | Output format: `text` or `json` |
| `-v`, `--verbose` | off | Verbose (debug) logging |
| `--threads` | `20` | Max concurrent requests (ceiling for adaptive backoff) |
| `--min-threads` | `2` | Floor concurrency the adaptive controller won't go below |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--rate` | `0` | Max requests per second (`0` = unlimited) |
| `--version` | — | Show version and exit |

## Output

**JSON mode** (`--format json`) emits results, stats, and detected tech:

```json
{
  "results": [
    {"url": "https://example.com/admin", "path": "admin", "status": 200, "length": 4521,
     "redirect_to": null, "depth": 0, "is_directory": false, "likely_false_positive": false, "duplicate_count": 1}
  ],
  "stats": {
    "total_tried": 150, "total_interesting": 3, "dedup_collapsed": 12,
    "throttle_events": 1, "soft_404_detected": true, "tech_detected": ["wordpress"]
  },
  "tech": {"technologies": ["wordpress"], "signals": {"wordpress": ["body contains 'wp-content'"]}}
}
```

## Project layout

```
dirbuster.py               Thin CLI entrypoint
hackdev_dirbuster/
  scanner.py                 Core scan engine: recursion, soft-404 detection, dedup, adaptive backoff
  fingerprint.py               Tech-stack detection (WordPress/Django/Laravel/Express)
  wordlists.py                  Default wordlist, tech-specific path lists, extension fan-out
  cli.py                        argparse wiring, output formatting
tests/                      pytest suite (see below)
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q
```

The suite includes a local test HTTP server (`tests/conftest.py`) simulating: a real directory that
redirects (proving recursion), a soft-404 wildcard that returns 200 for every unknown path (proving
baseline detection and filtering), a WordPress-like signal on the root page (proving tech
fingerprinting), and a path that 429s a few times before succeeding (proving the adaptive
backoff/retry logic actually recovers). Pure logic — wordlist merging/fan-out, body-fingerprint
hashing, dedup collapsing, soft-404 matching, and tech-signal analysis — is covered independently.

## Legal

This tool is intended **only** for authorized security testing — systems you own, or systems for
which you have obtained explicit written permission to test. Unauthorized scanning or brute-forcing
of systems you do not own or have permission to test may violate computer misuse laws in your
jurisdiction. The authors and contributors accept no liability for misuse of this software.
