"""
Wordlist handling: the built-in default wordlist, loading custom wordlists
from disk, extension fan-out, and merging in tech-specific path lists.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

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

# --------------------------------------------------------------------------
# Tech-stack-specific path lists, merged in automatically when the
# corresponding tech stack is fingerprinted on the target (see fingerprint.py)
# --------------------------------------------------------------------------
TECH_WORDLISTS: dict[str, list[str]] = {
    "wordpress": [
        "wp-content/", "wp-content/uploads/", "wp-content/plugins/",
        "wp-content/themes/", "wp-admin/", "wp-admin/install.php",
        "wp-json/", "wp-json/wp/v2/users", "wp-login.php", "wp-includes/",
        "wp-includes/js/", "xmlrpc.php", "wp-config.php.bak", "wp-cron.php",
        "wp-config-sample.php", "wp-content/debug.log",
    ],
    "django": [
        "admin/", "admin/login/", "static/admin/", "__debug__/", "media/",
        "api/", "api/v1/", "graphql", ".env", "settings.py", "manage.py",
        "django.log", "static/", "accounts/login/",
    ],
    "laravel": [
        ".env.example", "storage/", "storage/logs/laravel.log", "vendor/",
        "artisan", "public/index.php", "server.php", "bootstrap/cache/",
        "config/app.php", "routes/web.php", "telescope", "horizon",
    ],
    "express": [
        "node_modules/", "package.json", "package-lock.json", "api/",
        ".env", "server.js", "app.js", "index.js", "config/default.json",
    ],
}

# Status codes considered "interesting" by default.
DEFAULT_STATUS_CODES: set[int] = {200, 204, 301, 302, 307, 401, 403}

# A conservative default User-Agent so scans aren't trivially blocked by UA sniffing.
DEFAULT_USER_AGENT = "HackDev-DirBuster/2.0 (+https://github.com/raghubirrajmahato15/HackDev-DirBuster)"


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
        if extensions and not word.endswith("/") and "." not in word.rsplit("/", 1)[-1]:
            for ext in extensions:
                ext = ext.strip().lstrip(".")
                if ext:
                    add(f"{word}.{ext}")
    return expanded


def merge_tech_wordlist(words: list[str], tech_names: set[str]) -> list[str]:
    """Merge in tech-specific paths for every detected technology, de-duplicated."""
    if not tech_names:
        return list(words)

    merged: list[str] = list(words)
    seen: set[str] = set(words)
    for tech in sorted(tech_names):
        for path in TECH_WORDLISTS.get(tech, []):
            if path not in seen:
                seen.add(path)
                merged.append(path)
    return merged


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


def parse_extensions(raw: Optional[str]) -> list[str]:
    """Parse a comma-separated list of extensions."""
    if not raw:
        return []
    return [ext.strip().lstrip(".") for ext in raw.split(",") if ext.strip()]


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
