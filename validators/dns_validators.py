"""
dns_validators.py

Low-priority validators for DNS-related inputs.
Designed to prevent obvious mistakes while remaining compatible
with diverse DNS tools and server behaviors.

Used by:
- dnsenum, dnsrecon
- amass, sublist3r
- nmap DNS options
- ffuf host/header fuzzing

Validation only. No DNS queries performed.
"""

import re
import ipaddress


# -------------------------------------------------
# Regex patterns & constants
# -------------------------------------------------

# Domain name (RFC 1123-ish, permissive)
_DOMAIN_NAME = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Subdomain label (single label)
_SUBDOMAIN_LABEL = re.compile(r"^[A-Za-z0-9-]{1,63}$")

# DNS record types commonly used by tools
_DNS_RECORD_TYPES = {
    "A", "AAAA", "CNAME", "MX", "NS", "TXT",
    "SOA", "SRV", "PTR", "CAA", "NAPTR"
}

# DNS server IPs (IPv4/IPv6)
# (validated via ipaddress)


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_domain_name(value: str) -> bool:
    """
    Validate a domain name.

    Examples:
    - example.com
    - sub.domain.co.in
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip().lower()
    return bool(_DOMAIN_NAME.match(value))


def validate_subdomain(value: str) -> bool:
    """
    Validate a subdomain label.

    Example:
    - www
    - mail
    - api-v1
    """
    if not value or not isinstance(value, str):
        return False

    return bool(_SUBDOMAIN_LABEL.match(value.strip().lower()))


def validate_fqdn(value: str) -> bool:
    """
    Validate a fully-qualified domain name (FQDN).

    Accepts:
    - example.com
    - example.com.
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip().lower()
    if value.endswith("."):
        value = value[:-1]

    return validate_domain_name(value)


def validate_dns_record_type(value: str) -> bool:
    """
    Validate DNS record type.

    Examples:
    - A
    - MX
    - TXT
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().upper() in _DNS_RECORD_TYPES


def validate_multiple_dns_record_types(value: str) -> bool:
    """
    Validate comma-separated DNS record types.

    Example:
    - A,MX,TXT
    """
    if not value or not isinstance(value, str):
        return False

    types = [v.strip().upper() for v in value.split(",") if v.strip()]
    if not types:
        return False

    return all(t in _DNS_RECORD_TYPES for t in types)


def validate_dns_server(value: str) -> bool:
    """
    Validate DNS server address.

    Examples:
    - 8.8.8.8
    - 1.1.1.1
    - 2001:4860:4860::8888
    """
    if not value or not isinstance(value, str):
        return False

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def validate_multiple_dns_servers(value: str) -> bool:
    """
    Validate comma-separated DNS server addresses.

    Example:
    - 8.8.8.8,1.1.1.1
    """
    if not value or not isinstance(value, str):
        return False

    servers = [v.strip() for v in value.split(",") if v.strip()]
    if not servers:
        return False

    return all(validate_dns_server(s) for s in servers)


def validate_asn(value: str) -> bool:
    """
    Validate Autonomous System Number.

    Formats:
    - AS12345
    - 12345

    Examples:
    - AS13335
    - 13335
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip().upper()

    # Remove AS prefix if present
    if value.startswith("AS"):
        value = value[2:]

    # Check if it's a valid positive integer
    if not value.isdigit():
        return False

    asn = int(value)
    return asn > 0 and asn <= 4294967295  # Valid ASN range
