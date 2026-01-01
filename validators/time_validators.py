"""
time_validators.py
==================

Time format validators used across multiple tools:
- validate_time_format: Validate time format with optional units (ms, s, m, h)
- validate_time_range: Validate time range format (e.g., "0.1-2.0")
- validate_delay_format: Validate delay format (can be time or range)

Each validator raises ValueError with a helpful message if validation fails,
otherwise returns True.

Used by:
- nmap: --scan-delay, --host-timeout, --min-rtt-timeout, etc.
- nping: --delay (time format)
- ncat: -w, -i, -d (time formats)
- ffuf: -p (delay range: "0.1" or "0.1-2.0"), -timeout
- masscan: --wait, --retries
- sqlmap: (implicit timeouts)
"""

import re
from typing import Optional

# Time format pattern: number (integer or float) + optional unit (ms, s, m, h)
# Examples: "500ms", "30s", "2m", "0.5h", "10" (defaults to seconds)
_TIME_FORMAT_RE = re.compile(r'^(\d+(?:\.\d+)?)(ms|s|m|h)?$', re.IGNORECASE)

# Time range pattern: two numbers separated by dash
# Example: "0.1-2.0"
_TIME_RANGE_RE = re.compile(r'^(\d+(?:\.\d+)?)-(\d+(?:\.\d+)?)$')


def validate_time_format(value: str) -> bool:
    """
    Validate time format: number + optional unit (ms, s, m, h).
    
    Accepts:
    - Integer or float numbers (defaults to seconds if no unit)
    - Optional units: ms (milliseconds), s (seconds), m (minutes), h (hours)
    - Case-insensitive units
    
    Examples:
        "500ms"  -> Valid (500 milliseconds)
        "30s"    -> Valid (30 seconds)
        "2m"     -> Valid (2 minutes)
        "0.5h"   -> Valid (0.5 hours = 30 minutes)
        "10"     -> Valid (10 seconds, default)
        "1.5"    -> Valid (1.5 seconds, default)
    
    Args:
        value: Time string to validate
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If format is invalid
        
    Examples:
        >>> validate_time_format("500ms")
        True
        >>> validate_time_format("30s")
        True
        >>> validate_time_format("invalid")
        Traceback (most recent call last):
        ValueError: Invalid time format: 'invalid'. Expected format: number + optional unit (ms, s, m, h)
    """
    if not value or not isinstance(value, str):
        raise ValueError(
            f"Invalid time format: '{value}'. Expected format: number + optional unit (ms, s, m, h)"
        )
    
    value = value.strip()
    
    # Check if it matches the time format pattern
    match = _TIME_FORMAT_RE.match(value)
    if not match:
        raise ValueError(
            f"Invalid time format: '{value}'. Expected format: number + optional unit (ms, s, m, h). "
            f"Examples: '500ms', '30s', '2m', '0.5h', '10'"
        )
    
    number_str, unit = match.groups()
    
    # Validate that the number is positive
    try:
        number = float(number_str)
        if number < 0:
            raise ValueError(
                f"Invalid time format: '{value}'. Time value must be non-negative"
            )
    except ValueError as e:
        if "non-negative" in str(e):
            raise
        raise ValueError(
            f"Invalid time format: '{value}'. Could not parse number: '{number_str}'"
        )
    
    # Validate unit if provided
    if unit:
        unit_lower = unit.lower()
        if unit_lower not in ('ms', 's', 'm', 'h'):
            raise ValueError(
                f"Invalid time format: '{value}'. Unknown unit: '{unit}'. "
                f"Valid units: ms (milliseconds), s (seconds), m (minutes), h (hours)"
            )
    
    return True


def validate_time_range(value: str) -> bool:
    """
    Validate time range format: "min-max" (two numbers separated by dash).
    
    Used by tools like ffuf for delay ranges (e.g., "-p 0.1-2.0").
    
    Accepts:
    - Two numbers (integer or float) separated by a single dash
    - Both numbers must be non-negative
    - First number should be less than or equal to second number
    
    Examples:
        "0.1-2.0"  -> Valid (range from 0.1 to 2.0)
        "1-10"     -> Valid (range from 1 to 10)
        "5.5-5.5"  -> Valid (single value as range)
    
    Args:
        value: Time range string to validate
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If format is invalid
        
    Examples:
        >>> validate_time_range("0.1-2.0")
        True
        >>> validate_time_range("1-10")
        True
        >>> validate_time_range("invalid")
        Traceback (most recent call last):
        ValueError: Invalid time range format: 'invalid'. Expected format: min-max (e.g., "0.1-2.0")
    """
    if not value or not isinstance(value, str):
        raise ValueError(
            f"Invalid time range format: '{value}'. Expected format: min-max (e.g., '0.1-2.0')"
        )
    
    value = value.strip()
    
    # Check if it matches the time range pattern
    match = _TIME_RANGE_RE.match(value)
    if not match:
        raise ValueError(
            f"Invalid time range format: '{value}'. Expected format: min-max (e.g., '0.1-2.0'). "
            f"Two numbers separated by a single dash."
        )
    
    min_str, max_str = match.groups()
    
    # Validate that both numbers are valid and non-negative
    try:
        min_value = float(min_str)
        max_value = float(max_str)
        
        if min_value < 0 or max_value < 0:
            raise ValueError(
                f"Invalid time range format: '{value}'. Both values must be non-negative"
            )
        
        if min_value > max_value:
            raise ValueError(
                f"Invalid time range format: '{value}'. Minimum value ({min_value}) "
                f"cannot be greater than maximum value ({max_value})"
            )
            
    except ValueError as e:
        # Re-raise if it's our custom error
        if "non-negative" in str(e) or "cannot be greater" in str(e):
            raise
        raise ValueError(
            f"Invalid time range format: '{value}'. Could not parse numbers: '{min_str}' or '{max_str}'"
        )
    
    return True


def validate_delay_format(value: str) -> bool:
    """
    Validate delay format (can be time or range).
    
    This is a convenience validator that accepts either:
    - A single time value (validated by validate_time_format)
    - A time range (validated by validate_time_range)
    
    Used by tools that accept delays in either format (e.g., ffuf -p).
    
    Examples:
        "0.1"     -> Valid (single time value, defaults to seconds)
        "0.1s"    -> Valid (single time value with unit)
        "0.1-2.0" -> Valid (time range)
        "500ms"   -> Valid (single time value with milliseconds)
    
    Args:
        value: Delay string to validate (time or range)
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If format is invalid
        
    Examples:
        >>> validate_delay_format("0.1")
        True
        >>> validate_delay_format("0.1-2.0")
        True
        >>> validate_delay_format("500ms")
        True
        >>> validate_delay_format("invalid")
        Traceback (most recent call last):
        ValueError: Invalid delay format: 'invalid'. Expected time format or range (e.g., "0.1" or "0.1-2.0")
    """
    if not value or not isinstance(value, str):
        raise ValueError(
            f"Invalid delay format: '{value}'. Expected time format or range (e.g., '0.1' or '0.1-2.0')"
        )
    
    value = value.strip()
    
    # Check if it's a range first (contains dash)
    if '-' in value:
        # Try to validate as range
        try:
            return validate_time_range(value)
        except ValueError:
            # If range validation fails, try as single time (might be negative number)
            pass
    
    # Validate as single time format
    try:
        return validate_time_format(value)
    except ValueError as e:
        # Provide more helpful error message
        raise ValueError(
            f"Invalid delay format: '{value}'. Expected time format (e.g., '0.1', '500ms', '30s') "
            f"or range (e.g., '0.1-2.0'). Original error: {str(e)}"
        )


def parse_time_to_seconds(value: str) -> float:
    """
    Parse time format string to seconds (float).
    
    Converts time strings with units to seconds for comparison/calculation.
    This is a helper function, not a validator, but useful for adapters.
    
    Examples:
        "500ms"  -> 0.5
        "30s"    -> 30.0
        "2m"     -> 120.0
        "0.5h"   -> 1800.0
        "10"     -> 10.0
    
    Args:
        value: Time string to parse
        
    Returns:
        float: Time in seconds
        
    Raises:
        ValueError: If format is invalid
    """
    # First validate the format
    validate_time_format(value)
    
    value = value.strip()
    match = _TIME_FORMAT_RE.match(value)
    if not match:
        raise ValueError(f"Could not parse time format: '{value}'")
    
    number_str, unit = match.groups()
    number = float(number_str)
    
    # Convert to seconds based on unit
    if not unit:
        # Default to seconds
        return number
    elif unit.lower() == 'ms':
        return number / 1000.0
    elif unit.lower() == 's':
        return number
    elif unit.lower() == 'm':
        return number * 60.0
    elif unit.lower() == 'h':
        return number * 3600.0
    else:
        raise ValueError(f"Unknown time unit: '{unit}'")

