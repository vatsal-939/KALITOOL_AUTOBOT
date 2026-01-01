"""
rate_validators.py

Medium-priority validators for rate, delay, timing, and performance controls.
Reusable across tools such as:
- ffuf (-rate, -p delay)
- nmap (--min-rate, --max-rate, -T)
- nping (--rate, --delay)
- masscan (--rate)
- hping3 (--interval)

Validation only. No timing or network operations.
"""

import re


# -------------------------------------------------
# Constants & Regex
# -------------------------------------------------

# Time formats: seconds, ms, s, m, h (e.g., 500ms, 1.5s, 2m)
_TIME_REGEX = re.compile(r"^\d+(\.\d+)?(ms|s|m|h)?$")

# Range format: min-max (e.g., 0.1-2.0)
_RANGE_REGEX = re.compile(r"^\d+(\.\d+)?-\d+(\.\d+)?$")

# Timing template for nmap (-T0..-T5)
_TIMING_TEMPLATES = {0, 1, 2, 3, 4, 5}

# Reasonable safety bounds (soft validation)
_MIN_RATE = 0.0001   # packets/sec or req/sec
_MAX_RATE = 1_000_000


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_rate(value: str) -> bool:
    """
    Validate a rate value (requests/packets per second).

    Accepted:
    - integer or float > 0
    """
    try:
        rate = float(value)
        return _MIN_RATE <= rate <= _MAX_RATE
    except (ValueError, TypeError):
        return False


def validate_rate_or_zero(value: str) -> bool:
    """
    Validate rate allowing zero (meaning unlimited/default in some tools).
    """
    try:
        rate = float(value)
        return 0 <= rate <= _MAX_RATE
    except (ValueError, TypeError):
        return False


def validate_delay(value: str) -> bool:
    """
    Validate delay value.

    Accepted:
    - seconds (e.g., 0.5, 1, 2)
    - time-suffixed (e.g., 500ms, 1s, 2m, 1.5h)
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    return bool(_TIME_REGEX.match(value))


def validate_delay_range(value: str) -> bool:
    """
    Validate delay range.

    Example:
    - 0.1-2.0
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    return bool(_RANGE_REGEX.match(value))


def validate_min_max_rate(min_rate: str, max_rate: str) -> bool:
    """
    Validate a min/max rate pair.

    Ensures:
    - both are valid rates
    - min_rate <= max_rate
    """
    try:
        min_r = float(min_rate)
        max_r = float(max_rate)
        if min_r < 0 or max_r < 0:
            return False
        return min_r <= max_r <= _MAX_RATE
    except (ValueError, TypeError):
        return False


def validate_timing_template(value: str) -> bool:
    """
    Validate nmap timing template (-T0..-T5).
    """
    try:
        t = int(value)
        return t in _TIMING_TEMPLATES
    except (ValueError, TypeError):
        return False


def validate_timeout_seconds(value: str) -> bool:
    """
    Validate timeout expressed in seconds (integer or float > 0).
    """
    try:
        t = float(value)
        return t > 0
    except (ValueError, TypeError):
        return False
