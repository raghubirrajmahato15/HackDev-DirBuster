# HackDev-DirBuster

Concurrent directory and file brute-forcer with smart status-code filtering. Part of the [HackDev](https://github.com/raghubirrajmahato15) open-source cybersecurity toolkit. It walks a target web server's paths (from a built-in default list or a custom wordlist), optionally fanning each entry out across a set of file extensions, and reports back only the responses that actually look interesting — while automatically detecting and filtering out "soft 404" pages that would otherwise flood your results with false positives.

## Features

- Concurrent scanning via a `ThreadPoolExecutor` thread pool, sized with `--threads`
- Built-in default wordlist of ~100 common paths (admin panels, config files, `.git`, `.env`, backups, APIs, etc.) — no wordlist file required to get started
- `--wordlist` to supply your own list, one entry per line
- `--extensions` to fan each wordlist entry out across multiple file extensions (e.g. `php,html,js,txt,bak`)
- Configurable "interesting" status codes via `--status-codes` (defaults to `200,204,301,302,307,401,403`)
- Automatic soft-404 detection: probes a random nonexistent path first and filters out any real responses that match its status/length signature
- Redirect handling: off by default, records the `Location` header; `--follow-redirects` to follow them instead
- Simple global rate limiting via `--rate` (requests/second, `0` = unlimited)
- Per-request `--timeout`
- Text (readable table, sorted by status) and JSON (structured results + stats summary) output via `--format`
- Write results to a file with `-o/--output`, or print to stdout
- Verbose debug logging via `-v/--verbose`, all status/error messages go through Python's `logging` module

## Install

```bash
git clone https://github.com/raghubirrajmahato15/HackDev-DirBuster.git
cd HackDev-DirBuster
pip install -r requirements.txt
```

Requires Python 3.10+.

## Usage examples

Scan a target using the built-in default wordlist:

```bash
python dirbuster.py https://example.com
```

Use a custom wordlist and fan out across extensions:

```bash
python dirbuster.py https://example.com --wordlist wordlists/common.txt --extensions php,html,js,txt,bak
```

Tune concurrency, rate limit, and timeout:

```bash
python dirbuster.py https://example.com --threads 50 --rate 20 --timeout 5
```

Only care about 200s and 403s, and get JSON output written to a file:

```bash
python dirbuster.py https://example.com --status-codes 200,403 --format json -o results.json
```

Follow redirects instead of just recording them, with verbose logging:

```bash
python dirbuster.py https://example.com --follow-redirects -v
```

## CLI flag reference

| Flag | Default | Description |
|---|---|---|
| `target` (positional) | — | Base target URL, e.g. `https://example.com` |
| `--wordlist` | built-in ~100-entry list | Path to a custom wordlist file (one entry per line) |
| `--extensions` | none | Comma-separated extensions to append to each entry, e.g. `php,html,js,txt,bak` |
| `-o`, `--output` | stdout | Write results to this file instead of printing to stdout |
| `--format` | `text` | Output format: `text` or `json` |
| `-v`, `--verbose` | off | Enable verbose (debug) logging |
| `--threads` | `20` | Number of concurrent worker threads |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--rate` | `0` | Max requests per second across all threads (`0` = unlimited) |
| `--status-codes` | `200,204,301,302,307,401,403` | Comma-separated list of status codes treated as "interesting" |
| `--follow-redirects` | off | Follow HTTP redirects instead of just recording the `Location` header |

## Output

**Text mode** prints a readable table of interesting results sorted by status code, followed by a summary (total tried, total interesting, total errors, duration, and soft-404 baseline info if detected).

**JSON mode** (`--format json`) emits a document of the form:

```json
{
  "results": [
    {"url": "https://example.com/admin", "status": 200, "length": 4521, "redirect_to": null}
  ],
  "stats": {
    "total_tried": 150,
    "total_interesting": 3,
    "total_errors": 0,
    "duration_seconds": 4.21,
    "soft_404_detected": false,
    "baseline_status": 404,
    "baseline_length": 512
  }
}
```

## Legal

This tool is intended **only** for authorized security testing — systems you own, or systems for which you have obtained explicit written permission to test. Unauthorized scanning or brute-forcing of systems you do not own or have permission to test may violate computer misuse laws in your jurisdiction. The authors and contributors accept no liability for misuse of this software.
