"""
url_validators.py

Medium-priority validators for URL handling.
Reusable across tools such as:
- ffuf
- sqlmap / sqlmapapi
- nuclei
- whatweb
- nikto
- wpscan
- gobuster / dirsearch

Validation only. No network calls.
"""

import re
from urllib.parse import urlparse


# -------------------------------------------------
# Regex patterns
# -------------------------------------------------

# Allow http, https, ws, wss, ftp (common in Kali tools)
_ALLOWED_SCHEMES = {"http", "https", "ws", "wss", "ftp"}

# Basic domain (RFC 1123-ish) or IPv4 literal
_DOMAIN_OR_IP = re.compile(
    r"""
    ^
    (
        # domain
        (?!-)[A-Za-z0-9-]{1,63}(?<!-)
        (\.[A-Za-z0-9-]{1,63})*
        |
        # IPv4
        (\d{1,3}\.){3}\d{1,3}
    )
    $
    """,
    re.VERBOSE,
)

# Path characters allowed in most tools
_PATH_SAFE = re.compile(r"^[A-Za-z0-9\-._~/%]*$")

# Port range
_PORT_MIN = 1
_PORT_MAX = 65535


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_url(value: str, allow_no_scheme: bool = False) -> bool:
    """
    Validate a full URL.

    Accepted:
    - http://example.com
    - https://example.com/path
    - http://127.0.0.1:8080
    - ws://host
    - ftp://host/path

    If allow_no_scheme=True, URLs like example.com/path are allowed.
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    # If scheme is missing but allowed, prepend dummy scheme for parsing
    test_value = value
    if "://" not in value:
        if not allow_no_scheme:
            return False
        test_value = "http://" + value

    try:
        parsed = urlparse(test_value)
    except Exception:
        return False

    # Scheme
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False

    # Host
    if not parsed.hostname:
        return False

    if not _DOMAIN_OR_IP.match(parsed.hostname):
        return False

    # Port
    if parsed.port is not None:
        if not (_PORT_MIN <= parsed.port <= _PORT_MAX):
            return False

    # Path
    if parsed.path and not _PATH_SAFE.match(parsed.path):
        return False

    return True


def validate_base_url(value: str) -> bool:
    """
    Validate a base URL (scheme + host [+ port], no query requirement).

    Used for:
    - ffuf -u
    - nuclei -u
    - whatweb
    """
    return validate_url(value, allow_no_scheme=False)


def validate_url_or_path(value: str) -> bool:
    """
    Validate either:
    - a full URL
    - or a relative path (/admin, /login.php)

    Useful for fuzzing tools (ffuf, dirsearch).
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    # Relative path
    if value.startswith("/"):
        return bool(_PATH_SAFE.match(value))

    # Full URL
    return validate_url(value, allow_no_scheme=False)


def validate_proxy_url(value: str) -> bool:
    """
    Validate proxy URLs.

    Accepted:
    - http://127.0.0.1:8080
    - socks5://127.0.0.1:9050
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    if "://" not in value:
        return False

    parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https", "socks4", "socks5"}:
        return False

    if not parsed.hostname:
        return False

    if parsed.port is None:
        return False

    return _PORT_MIN <= parsed.port <= _PORT_MAX


def validate_multiple_urls(value: str) -> bool:
    """
    Validate comma-separated list of URLs.

    Example:
    - https://a.com,https://b.com
    """
    if not value or not isinstance(value, str):
        return False

    urls = [v.strip() for v in value.split(",") if v.strip()]
    if not urls:
        return False

    for url in urls:
        if not validate_url(url, allow_no_scheme=False):
            return False

    return True
