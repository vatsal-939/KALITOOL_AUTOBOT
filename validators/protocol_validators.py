"""
protocol_validators.py

Protocol-level validators for TCP, ICMP, ARP, IP and Ethernet options.
Used across nmap, nping, ncat, masscan.
"""

import re
from typing import Optional

# =========================
# TCP VALIDATORS
# =========================

_TCP_FLAGS = {"SYN", "ACK", "FIN", "RST", "PSH", "URG"}


def validate_tcp_flags(value: str) -> bool:
    """
    Validate TCP flag combinations.

    Accepted formats:
    - "SYN"
    - "ACK,PSH"
    - "SYN,ACK,RST"

    Notes:
    - Order does not matter
    - Case-insensitive
    - Used by: nmap --scanflags, nping --flags
    """
    if not isinstance(value, str) or not value.strip():
        return False

    flags = {f.strip().upper() for f in value.split(",")}
    return flags.issubset(_TCP_FLAGS)


# =========================
# ICMP VALIDATORS
# =========================

def validate_icmp_type(value: str) -> bool:
    """
    Validate ICMP type (0–255).

    Notes:
    - Numeric only
    - Used by nping --icmp-type
    """
    if not value.isdigit():
        return False
    return 0 <= int(value) <= 255


def validate_icmp_code(value: str, icmp_type: Optional[str] = None) -> bool:
    """
    Validate ICMP code (0–255).

    Notes:
    - Numeric only
    - ICMP code meaning depends on ICMP type
    - This validator checks numeric range only
    - Used by nping --icmp-code
    """
    if not value.isdigit():
        return False
    return 0 <= int(value) <= 255


# =========================
# ARP / RARP VALIDATORS
# =========================

_ARP_TYPES = {
    "ARP": 1,
    "ARP-REPLY": 2,
    "RARP": 3,
    "RARP-REPLY": 4,
}


def validate_arp_type(value: str) -> bool:
    """
    Validate ARP/RARP type.

    Accepted values:
    - Names: ARP, ARP-reply, RARP, RARP-reply
    - Numbers: 1, 2, 3, 4

    Used by: nping --arp-type
    """
    if value.isdigit():
        return int(value) in _ARP_TYPES.values()

    value = value.upper()
    return value in _ARP_TYPES


# =========================
# IP PROTOCOL VALIDATOR
# =========================

_IP_PROTOCOLS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "SCTP": 132,
}


def validate_ip_protocol(value: str) -> bool:
    """
    Validate IP protocol.

    Accepted:
    - Numeric protocol (0–255)
    - Common names: tcp, udp, icmp, sctp

    Used by:
    - nmap -PO
    - nping protocol-level operations
    """
    if value.isdigit():
        return 0 <= int(value) <= 255

    return value.upper() in _IP_PROTOCOLS


# =========================
# ETHERNET VALIDATOR
# =========================

def validate_ether_type(value: str) -> bool:
    """
    Validate Ethernet EtherType.

    Accepted formats:
    - Hex: 0x0800
    - Decimal: 2048

    Notes:
    - EtherType is 16-bit (0–65535)
    - Used by nping --ether-type
    """
    if value.startswith(("0x", "0X")):
        try:
            return 0 <= int(value, 16) <= 0xFFFF
        except ValueError:
            return False

    if value.isdigit():
        return 0 <= int(value) <= 65535

    return False
