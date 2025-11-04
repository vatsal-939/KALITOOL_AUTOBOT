"""
input_validators.py
====================
Provides reusable validation functions for user input
across all KaliToolAutoBot modules.
"""

import os
import re
import ipaddress


# ----------------------------------------------------------------------
# IP and Network Validation
# ----------------------------------------------------------------------
def validate_ip(ip: str) -> bool:
    """Check if input is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ip_or_range(value: str) -> bool:
    """Validate single IP or CIDR range (e.g., 192.168.0.0/24)."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


# ----------------------------------------------------------------------
# Hostname and Domain Validation
# ----------------------------------------------------------------------
def validate_hostname(hostname: str) -> bool:
    """Validate domain or hostname."""
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    return re.match(pattern, hostname) is not None


def validate_url(url: str) -> bool:
    """Validate basic URL syntax."""
    pattern = r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
    return re.match(pattern, url) is not None


# ----------------------------------------------------------------------
# Port Validation
# ----------------------------------------------------------------------
def validate_port(port: str) -> bool:
    """Check if port is an integer within valid range (1–65535)."""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except ValueError:
        return False


def validate_port_range(value: str) -> bool:
    """Validate comma-separated port lists or ranges (e.g., 22,80,443 or 1-65535)."""
    pattern = r"^(\d{1,5}(-\d{1,5})?)(,(\d{1,5}(-\d{1,5})?))*$"
    return re.match(pattern, value) is not None


# ----------------------------------------------------------------------
# File and Path Validation
# ----------------------------------------------------------------------
def validate_file_exists(path: str) -> bool:
    """Check if file exists."""
    return os.path.isfile(path)


def validate_directory(path: str) -> bool:
    """Check if directory exists."""
    return os.path.isdir(path)


def validate_output_path(path: str) -> bool:
    """Ensure output path is writable."""
    directory = os.path.dirname(path) or "."
    return os.access(directory, os.W_OK)


# ----------------------------------------------------------------------
# General Validation Helpers
# ----------------------------------------------------------------------
def validate_yes_no(answer: str) -> bool:
    """Check if input is 'y', 'n', 'yes', or 'no'."""
    return answer.lower() in ["y", "yes", "n", "no"]


def validate_integer(value: str) -> bool:
    """Validate that input is an integer."""
    try:
        int(value)
        return True
    except ValueError:
        return False


def validate_float(value: str) -> bool:
    """Validate that input is a floating point number."""
    try:
        float(value)
        return True
    except ValueError:
        return False


def validate_non_empty(value: str) -> bool:
    """Ensure input is not empty or whitespace."""
    return bool(value and value.strip())


# ----------------------------------------------------------------------
# Combined Validator Loader (Optional)
# ----------------------------------------------------------------------
def get_validator(name: str):
    """
    Dynamically return validator function by name.
    Example: get_validator("validate_ip") returns function reference.
    """
    return globals().get(name)
