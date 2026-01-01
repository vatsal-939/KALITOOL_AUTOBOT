"""
ssl_validators.py

Medium-priority validators for SSL/TLS–related inputs.
Reusable across tools such as:
- nmap / ncat (SSL flags, certs, ciphers, SNI)
- ffuf (TLS/SNI)
- sqlmap (HTTPS targets)
- nuclei / bettercap

Validation only. No filesystem reads or network calls.
"""

import os
import re


# -------------------------------------------------
# Regex patterns
# -------------------------------------------------

# Cipher suite tokens (OpenSSL-style lists)
# Examples: HIGH, !aNULL, ECDHE-RSA-AES128-GCM-SHA256
_CIPHER_TOKEN = re.compile(r"^[A-Za-z0-9_\-!:+@.]+$")

# SNI hostname (RFC 1123-ish)
_SNI_HOSTNAME = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)

# TLS versions commonly accepted
_TLS_VERSIONS = {
    "ssl2", "ssl3",
    "tls1", "tls1.0", "tls1.1", "tls1.2", "tls1.3"
}

# ALPN protocol tokens (e.g., http/1.1, h2)
_ALPN_TOKEN = re.compile(r"^[A-Za-z0-9_\-./]+$")


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_ssl_enable(value: str | bool) -> bool:
    """
    Validate SSL enable flag.

    Accepts:
    - True / False
    - 'true', 'false', 'yes', 'no'
    """
    if isinstance(value, bool):
        return True
    if not isinstance(value, str):
        return False
    return value.strip().lower() in {"true", "false", "yes", "no", "1", "0"}


def validate_certificate_path(value: str) -> bool:
    """
    Validate SSL certificate or key file path.

    Checks:
    - non-empty string
    - reasonable filename extension
    - path syntax only (does NOT require file to exist)
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    if not value:
        return False

    # Common cert/key extensions
    valid_ext = (
        value.endswith(".pem") or
        value.endswith(".crt") or
        value.endswith(".cer") or
        value.endswith(".key")
    )

    return valid_ext and os.path.basename(value) != ""


def validate_cipher_list(value: str) -> bool:
    """
    Validate SSL cipher list.

    Accepted:
    - Single token: HIGH
    - OpenSSL-style list: HIGH:!aNULL:!MD5
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    if not value:
        return False

    tokens = value.split(":")
    for token in tokens:
        if not _CIPHER_TOKEN.match(token):
            return False

    return True


def validate_tls_version(value: str) -> bool:
    """
    Validate TLS/SSL protocol version.

    Accepted:
    - ssl2, ssl3
    - tls1, tls1.0, tls1.1, tls1.2, tls1.3
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _TLS_VERSIONS


def validate_sni_hostname(value: str) -> bool:
    """
    Validate Server Name Indication (SNI) hostname.

    Example:
    - example.com
    - sub.domain.org
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    return bool(_SNI_HOSTNAME.match(value))


def validate_alpn_protocols(value: str) -> bool:
    """
    Validate ALPN protocol list.

    Example:
    - h2
    - http/1.1
    - h2,http/1.1
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    tokens = [v.strip() for v in value.split(",") if v.strip()]
    if not tokens:
        return False

    for token in tokens:
        if not _ALPN_TOKEN.match(token):
            return False

    return True
