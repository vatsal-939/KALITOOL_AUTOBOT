"""
target_validators.py

High-priority validators for complex target specification used by
nmap, nping, masscan and similar tools.

Covers:
- Single IP
- CIDR notation
- IP ranges (nmap-style)
- Hostnames
- Comma-separated target lists
- Random target count (-iR)

Does NOT execute anything – validation only.
"""

import re
import ipaddress


# -------------------------------------------------
# Core helpers
# -------------------------------------------------

_IP_RANGE_REGEX = re.compile(
    r"""
    ^
    (\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})\.(\d{1,3})-(\d{1,3})
    $
    |
    ^
    (\d{1,3})-(\d{1,3})\.(\d{1,3})\.(\d{1,3})
    $
    """,
    re.VERBOSE,
)

_HOSTNAME_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_nmap_target(value: str) -> bool:
    """
    Validate a single nmap-style target.

    Allowed formats:
    - IPv4 / IPv6
    - CIDR (192.168.1.0/24)
    - IP range (192.168.0-255.1-254)
    - Hostname (scanme.nmap.org)
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    # Try IP (v4/v6)
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    # Try CIDR
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass

    # Try IP range (nmap-style)
    if _IP_RANGE_REGEX.match(value):
        return _validate_ip_range(value)

    # Try hostname
    if _HOSTNAME_REGEX.match(value):
        return True

    return False


def validate_target_list(value: str) -> bool:
    """
    Validate comma-separated list of targets.

    Example:
    - "192.168.1.1,10.0.0.1,scanme.nmap.org"
    """
    if not value or not isinstance(value, str):
        return False

    targets = [v.strip() for v in value.split(",") if v.strip()]
    if not targets:
        return False

    for target in targets:
        if not validate_nmap_target(target):
            return False

    return True


def validate_target_count(value: str) -> bool:
    """
    Validate random target count (-iR).

    Must be a positive integer.
    """
    try:
        count = int(value)
        return count > 0
    except (ValueError, TypeError):
        return False


# -------------------------------------------------
# Internal helpers
# -------------------------------------------------

def _validate_ip_range(value: str) -> bool:
    """
    Validate nmap-style IP range parts.

    Example:
    192.168.0-255.1-254
    """
    parts = re.split(r"[.-]", value)
    try:
        nums = [int(p) for p in parts if p.isdigit()]
        return all(0 <= n <= 255 for n in nums)
    except ValueError:
        return False
