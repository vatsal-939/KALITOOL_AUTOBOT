"""
ffuf_validators.py

Low-priority, ffuf-specific validators.
These validators are intentionally permissive and focus on
preventing obvious input mistakes rather than strict enforcement.

Used by:
- ffuf adapters only
"""

import re
import os


# -------------------------------------------------
# Constants & Regex
# -------------------------------------------------

# ffuf keyword (FUZZ, PARAM, VAL, etc.)
_FFUF_KEYWORD = re.compile(r"^[A-Z0-9_]{2,20}$")

# Recursion strategy
_RECURSION_STRATEGIES = {"default", "greedy"}

# Output formats supported by ffuf
_OUTPUT_FORMATS = {"json", "ejson", "html", "md", "csv", "ecsv", "all"}

# Match/filter operators
_MATCH_OPERATORS = {"and", "or"}

# Encoding tokens
_ENCODER_TOKEN = re.compile(r"^[a-zA-Z0-9_-]+$")


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_ffuf_keyword(value: str) -> bool:
    """
    Validate ffuf keyword.

    Examples:
    - FUZZ
    - PARAM
    - VAL
    """
    if not value or not isinstance(value, str):
        return False

    return bool(_FFUF_KEYWORD.match(value.strip()))


def validate_wordlist_spec(value: str) -> bool:
    """
    Validate ffuf wordlist specification.

    Accepted:
    - /path/to/wordlist.txt
    - /path/to/wordlist.txt:KEYWORD
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()

    if ":" in value:
        path, keyword = value.split(":", 1)
        return bool(path) and validate_ffuf_keyword(keyword)

    return bool(value)


def validate_recursion_strategy(value: str) -> bool:
    """
    Validate recursion strategy.

    Allowed:
    - default
    - greedy
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _RECURSION_STRATEGIES


def validate_match_operator(value: str) -> bool:
    """
    Validate matcher/filter operator.

    Allowed:
    - and
    - or
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _MATCH_OPERATORS


def validate_ffuf_output_format(value: str) -> bool:
    """
    Validate ffuf output format.

    Allowed:
    - json, ejson, html, md, csv, ecsv, all
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _OUTPUT_FORMATS


def validate_ffuf_encoders(value: str) -> bool:
    """
    Validate ffuf encoder list.

    Example:
    - urlencode
    - urlencode b64encode
    """
    if not value or not isinstance(value, str):
        return False

    tokens = [v.strip() for v in value.split() if v.strip()]
    if not tokens:
        return False

    return all(_ENCODER_TOKEN.match(token) for token in tokens)


def validate_calibration_string(value: str) -> bool:
    """
    Validate auto-calibration strings.

    ffuf allows arbitrary strings, so this only checks non-empty.
    """
    return isinstance(value, str) and value.strip() != ""


def validate_input_command(value: str) -> bool:
    """
    Validate --input-cmd value.

    ffuf executes this command internally, so we only ensure:
    - non-empty string
    - no newline injection
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    return value != "" and "\n" not in value
