"""
format_validators.py

Low-priority validators for common output and formatting options.
Used across tools such as:
- nmap (output formats)
- ffuf (output formats)
- sqlmap (dump/output formats)
- masscan (output files)
- generic CLI formatting flags

Validation only. No file creation or parsing.
"""

import re


# -------------------------------------------------
# Constants & Regex
# -------------------------------------------------

# Common output formats used across Kali tools
_COMMON_FORMATS = {
    "txt", "text",
    "json", "xml", "yaml", "yml",
    "csv", "html", "md",
    "grepable", "normal"
}

# Filename-safe characters (no path traversal)
_FILENAME_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")

# Format lists (comma-separated)
_FORMAT_LIST = re.compile(r"^[A-Za-z0-9,._-]+$")

# Boolean-like values
_BOOLEAN_VALUES = {"true", "false", "yes", "no", "1", "0"}


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_output_format(value: str) -> bool:
    """
    Validate a single output format.

    Examples:
    - json
    - xml
    - html
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _COMMON_FORMATS


def validate_multiple_output_formats(value: str) -> bool:
    """
    Validate comma-separated output formats.

    Example:
    - json,xml,html
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    if not _FORMAT_LIST.match(value):
        return False

    formats = [v.strip().lower() for v in value.split(",") if v.strip()]
    if not formats:
        return False

    return all(f in _COMMON_FORMATS for f in formats)


def validate_filename(value: str) -> bool:
    """
    Validate output filename (no directory traversal).

    Examples:
    - scan.json
    - output.xml
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    # Disallow path separators
    if "/" in value or "\\" in value:
        return False

    return bool(_FILENAME_SAFE.match(value))


def validate_basename(value: str) -> bool:
    """
    Validate basename used for multi-format output.

    Example:
    - scan
    - report_01
    """
    return validate_filename(value)


def validate_boolean_flag(value: str) -> bool:
    """
    Validate generic boolean-like flag values.

    Accepted:
    - true / false
    - yes / no
    - 1 / 0
    """
    if isinstance(value, bool):
        return True

    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _BOOLEAN_VALUES


def validate_format_string(value: str) -> bool:
    """
    Validate generic format strings.

    Used where tools accept free-form format names
    but still require basic sanity.

    Example:
    - custom
    - extended_json
    """
    if not value or not isinstance(value, str):
        return False

    return bool(re.match(r"^[A-Za-z0-9_-]{1,64}$", value.strip()))
