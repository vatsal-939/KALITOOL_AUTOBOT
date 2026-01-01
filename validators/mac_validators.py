"""
mac_validators.py

Medium-priority validators for MAC address handling.
Used by tools such as:
- nmap (--spoof-mac)
- macchanger
- bettercap
- arpwatch / arping
- masscan (adapter/router MAC)

Validation only. No system calls.
"""

import re


# -------------------------------------------------
# Regex patterns
# -------------------------------------------------

# 00:11:22:33:44:55
_MAC_COLON = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# 00-11-22-33-44-55
_MAC_DASH = re.compile(r"^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$")

# 001122334455
_MAC_PLAIN = re.compile(r"^[0-9A-Fa-f]{12}$")

# Vendor name (for nmap --spoof-mac vendor)
_VENDOR_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{1,31}$")


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_mac_address(value: str) -> bool:
    """
    Validate standard MAC address formats.

    Accepted:
    - 00:11:22:33:44:55
    - 00-11-22-33-44-55
    - 001122334455
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    return (
        bool(_MAC_COLON.match(value)) or
        bool(_MAC_DASH.match(value)) or
        bool(_MAC_PLAIN.match(value))
    )


def validate_mac_prefix(value: str) -> bool:
    """
    Validate MAC prefix (vendor prefix).

    Example:
    - 00:11:22
    - 00-11-22
    - 001122
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    if ":" in value:
        parts = value.split(":")
    elif "-" in value:
        parts = value.split("-")
    else:
        parts = [value[i:i + 2] for i in range(0, len(value), 2)]

    if len(parts) != 3:
        return False

    try:
        return all(0 <= int(p, 16) <= 255 for p in parts)
    except ValueError:
        return False


def validate_mac_vendor(value: str) -> bool:
    """
    Validate vendor name input for tools like:
    nmap --spoof-mac <vendor>

    Example:
    - Cisco
    - Apple
    - Intel Corporation
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    return bool(_VENDOR_NAME.match(value))


def validate_spoof_mac(value: str) -> bool:
    """
    Combined validator for spoof-mac options.

    Accepts:
    - Full MAC
    - MAC prefix
    - Vendor name
    """
    return (
        validate_mac_address(value) or
        validate_mac_prefix(value) or
        validate_mac_vendor(value)
    )
