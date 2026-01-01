"""
http_validators.py

Medium-priority validators for HTTP-related inputs.
Reusable across tools such as:
- ffuf
- sqlmap / sqlmapapi
- nuclei
- whatweb
- nikto
- wpscan
- burpsuite-integrated flows

Validation only. No network operations.
"""

import re


# -------------------------------------------------
# Constants & Regex
# -------------------------------------------------

# Valid HTTP methods
_HTTP_METHODS = {
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT"
}

# HTTP header name (RFC 7230)
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# HTTP header value (printable ASCII except control chars)
_HEADER_VALUE = re.compile(r"^[\x20-\x7E]*$")

# Cookie name=value pairs
_COOKIE_PAIR = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+=[^;]*$")

# HTTP status codes
_STATUS_CODE_MIN = 100
_STATUS_CODE_MAX = 599

# HTTP protocol versions
_HTTP_VERSIONS = {"1.0", "1.1", "2", "2.0"}


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_http_method(value: str) -> bool:
    """
    Validate HTTP method.

    Examples:
    - GET
    - POST
    - PUT
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().upper() in _HTTP_METHODS


def validate_http_header(value: str) -> bool:
    """
    Validate a single HTTP header.

    Format:
    - Name: Value
    """
    if not value or not isinstance(value, str):
        return False

    if ":" not in value:
        return False

    name, val = value.split(":", 1)
    name = name.strip()
    val = val.strip()

    if not name or not _HEADER_NAME.match(name):
        return False

    return bool(_HEADER_VALUE.match(val))


def validate_multiple_http_headers(value: str) -> bool:
    """
    Validate comma-separated HTTP headers.

    Example:
    - Host:example.com,User-Agent:test
    """
    if not value or not isinstance(value, str):
        return False

    headers = [v.strip() for v in value.split(",") if v.strip()]
    if not headers:
        return False

    return all(validate_http_header(h) for h in headers)


def validate_http_cookie(value: str) -> bool:
    """
    Validate HTTP Cookie header value.

    Example:
    - PHPSESSID=abc123
    - user=admin; token=xyz
    """
    if not value or not isinstance(value, str):
        return False

    pairs = [v.strip() for v in value.split(";") if v.strip()]
    if not pairs:
        return False

    return all(_COOKIE_PAIR.match(p) for p in pairs)


def validate_http_status_codes(value: str) -> bool:
    """
    Validate HTTP status code or ranges.

    Examples:
    - 200
    - 200-299
    - 200,301,403
    """
    if not value or not isinstance(value, str):
        return False

    parts = [v.strip() for v in value.split(",") if v.strip()]
    if not parts:
        return False

    for part in parts:
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                if not (_STATUS_CODE_MIN <= start <= end <= _STATUS_CODE_MAX):
                    return False
            except ValueError:
                return False
        else:
            try:
                code = int(part)
                if not (_STATUS_CODE_MIN <= code <= _STATUS_CODE_MAX):
                    return False
            except ValueError:
                return False

    return True


def validate_http_version(value: str) -> bool:
    """
    Validate HTTP protocol version.

    Examples:
    - 1.1
    - 2
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip() in _HTTP_VERSIONS


def validate_http_timeout(value: str) -> bool:
    """
    Validate HTTP timeout (seconds).

    Must be positive integer or float.
    """
    try:
        timeout = float(value)
        return timeout > 0
    except (ValueError, TypeError):
        return False


def validate_user_agent(value: str) -> bool:
    """
    Validate User-Agent string.

    Allows any printable ASCII characters.
    """
    if not value or not isinstance(value, str):
        return False

    return bool(_HEADER_VALUE.match(value))
