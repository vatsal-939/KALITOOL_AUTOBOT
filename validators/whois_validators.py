"""
whois_validators.py

Low-priority, whois-specific validators.
These validators focus on preventing obvious user mistakes while
keeping compatibility with multiple WHOIS servers.

Used by:
- whois adapters only
"""

import re
import ipaddress


# -------------------------------------------------
# Regex patterns
# -------------------------------------------------

# WHOIS object: domain, ASN, handle, name, etc.
_WHOIS_OBJECT = re.compile(
    r"^[A-Za-z0-9._:-]{1,255}$"
)

# RIPE attributes (mnt-by, admin-c, tech-c, etc.)
_RIPE_ATTRIBUTE = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]{1,31}$"
)

# RIPE object types (inetnum, aut-num, route, person, role, etc.)
_RIPE_OBJECT_TYPE = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]{1,31}$"
)

# Source database name (RIPE, ARIN, APNIC, etc.)
_SOURCE_NAME = re.compile(
    r"^[A-Za-z][A-Za-z0-9-]{1,31}$"
)

# Serial range FIRST-LAST
_SERIAL_RANGE = re.compile(
    r"^[A-Za-z]+:\d+-\d+$"
)

# Query info
_QUERY_INFO = {"version", "sources", "types"}


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_whois_object(value: str) -> bool:
    """
    Validate WHOIS query object.

    Examples:
    - example.com
    - 8.8.8.8
    - AS13335
    - inetnum handle
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    # IP address
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    # Domain / ASN / handle
    return bool(_WHOIS_OBJECT.match(value))


def validate_ripe_attribute(value: str) -> bool:
    """
    Validate RIPE inverse lookup attribute.

    Examples:
    - mnt-by
    - admin-c
    - tech-c
    """
    if not value or not isinstance(value, str):
        return False

    return bool(_RIPE_ATTRIBUTE.match(value.strip()))


def validate_multiple_ripe_attributes(value: str) -> bool:
    """
    Validate comma-separated RIPE attributes.

    Example:
    - mnt-by,admin-c
    """
    if not value or not isinstance(value, str):
        return False

    attrs = [v.strip() for v in value.split(",") if v.strip()]
    if not attrs:
        return False

    return all(validate_ripe_attribute(attr) for attr in attrs)


def validate_ripe_object_type(value: str) -> bool:
    """
    Validate RIPE object type.

    Examples:
    - inetnum
    - aut-num
    - route
    """
    if not value or not isinstance(value, str):
        return False

    return bool(_RIPE_OBJECT_TYPE.match(value.strip()))


def validate_multiple_ripe_object_types(value: str) -> bool:
    """
    Validate comma-separated RIPE object types.
    """
    if not value or not isinstance(value, str):
        return False

    types = [v.strip() for v in value.split(",") if v.strip()]
    if not types:
        return False

    return all(validate_ripe_object_type(t) for t in types)


def validate_whois_source(value: str) -> bool:
    """
    Validate WHOIS source database.

    Examples:
    - RIPE
    - ARIN
    - APNIC
    """
    if not value or not isinstance(value, str):
        return False

    return bool(_SOURCE_NAME.match(value.strip()))


def validate_multiple_whois_sources(value: str) -> bool:
    """
    Validate comma-separated WHOIS sources.

    Example:
    - RIPE,ARIN
    """
    if not value or not isinstance(value, str):
        return False

    sources = [v.strip() for v in value.split(",") if v.strip()]
    if not sources:
        return False

    return all(validate_whois_source(src) for src in sources)


def validate_serial_range(value: str) -> bool:
    """
    Validate RIPE serial range.

    Format:
    - SOURCE:FIRST-LAST
    Example:
    - RIPE:12345-67890
    """
    if not value or not isinstance(value, str):
        return False

    return bool(_SERIAL_RANGE.match(value.strip()))


def validate_query_info(value: str) -> bool:
    """
    Validate -q query information.

    Allowed:
    - version
    - sources
    - types
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _QUERY_INFO
