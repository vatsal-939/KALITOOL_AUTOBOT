"""
validators/network_validators.py

Common network-related validators used by manifests:
- validate_ip
- validate_ipv4
- validate_ipv6
- validate_cidr
- validate_hostname
- validate_host_and_port
- validate_port
- validate_port_optional
- validate_host_or_path (for unix socket paths)
Each validator raises ValueError with a helpful message if validation fails,
otherwise returns True (or normalized value where noted).
"""

import ipaddress
import re
import os
from typing import Tuple

# hostname pattern: allow letters, digits, hyphen and dot (simple)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*(?:[A-Za-z0-9\-]{1,63})$")


def validate_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except Exception:
        raise ValueError(f"Invalid IPv4 address: '{value}'")


def validate_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except Exception:
        raise ValueError(f"Invalid IPv6 address: '{value}'")


def validate_ip(value: str) -> bool:
    # Try both v4 and v6
    try:
        return validate_ipv4(value)
    except ValueError:
        return validate_ipv6(value)


def validate_cidr(value: str) -> bool:
    # Accept IPv4/IPv6 CIDR (e.g., 192.168.0.0/24 or 2001:db8::/32)
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except Exception:
        raise ValueError(f"Invalid CIDR/network: '{value}'")


def validate_hostname(value: str) -> bool:
    if _HOSTNAME_RE.match(value):
        return True
    raise ValueError(f"Invalid hostname: '{value}'")


def validate_host_or_path(value: str) -> bool:
    """
    Accept hostnames, IPs, or unix socket paths (absolute path).
    - If it is an existing filesystem path, accept it (for -U unix sockets).
    - Otherwise validate as hostname or IP.
    """
    if os.path.exists(value):
        return True
    try:
        return validate_ip(value)
    except ValueError:
        return validate_hostname(value)


def _split_host_port(value: str) -> Tuple[str, int]:
    if ":" not in value:
        raise ValueError(f"Expected host:port but got '{value}'")
    host, port_str = value.rsplit(":", 1)
    if not port_str.isdigit():
        raise ValueError(f"Port must be numeric in '{value}'")
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range (1-65535) in '{value}'")
    # validate host part
    try:
        validate_ip(host)
    except ValueError:
        # not IP, check hostname
        validate_hostname(host)
    return host, port


def validate_host_and_port(value: str) -> bool:
    _split_host_port(value)
    return True


def validate_port(value: str) -> bool:
    if isinstance(value, int):
        port = value
    else:
        if not str(value).isdigit():
            raise ValueError(f"Invalid port: '{value}'")
        port = int(value)
    if 1 <= port <= 65535:
        return True
    raise ValueError(f"Port must be between 1 and 65535: '{value}'")


def validate_port_optional(value: str) -> bool:
    # empty allowed (e.g., unix socket mode)
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return True
    return validate_port(value)


def validate_hostport_or_port(value: str) -> bool:
    # Accept either "1234" or "host:1234"
    if ":" in value:
        return validate_host_and_port(value)
    return validate_port(value)
