"""
sql_validators.py

Medium-priority validators for SQL-related inputs.
Reusable across tools such as:
- sqlmap / sqlmapapi
- sqlninja
- sqlsus
- Burp-assisted SQLi workflows

Validation only. No database or network operations.
"""

import re


# -------------------------------------------------
# Regex patterns
# -------------------------------------------------

# SQL identifier: database, table, column
# Allows: db, db_name, schema.table, table.column
_SQL_IDENTIFIER = re.compile(
    r"""
    ^
    [A-Za-z_][A-Za-z0-9_]*               # first identifier
    (\.[A-Za-z_][A-Za-z0-9_]*)*          # optional dotted identifiers
    $
    """,
    re.VERBOSE,
)

# SQL keyword list for sqlmap --technique
_SQL_TECHNIQUES = {"B", "E", "U", "S", "T", "Q"}

# SQL DBMS identifiers commonly used by sqlmap
_SQL_DBMS = {
    "mysql", "postgresql", "postgres",
    "mssql", "oracle", "sqlite",
    "mariadb", "db2", "firebird",
    "sybase", "informix"
}

# Simple SQL boolean expressions (used in filters/payload checks)
_SQL_BOOLEAN_EXPR = re.compile(
    r"""
    ^
    [A-Za-z0-9_'\"().\s=<>!+-/*%]+
    $
    """,
    re.VERBOSE,
)


# -------------------------------------------------
# Public Validators
# -------------------------------------------------

def validate_sql_identifier(value: str) -> bool:
    """
    Validate SQL identifiers such as:
    - database
    - table
    - column
    - schema.table
    - table.column
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    return bool(_SQL_IDENTIFIER.match(value))


def validate_multiple_sql_identifiers(value: str) -> bool:
    """
    Validate comma-separated SQL identifiers.

    Example:
    - users,accounts,orders
    - db1.users,db2.accounts
    """
    if not value or not isinstance(value, str):
        return False

    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items:
        return False

    return all(validate_sql_identifier(item) for item in items)


def validate_sql_dbms(value: str) -> bool:
    """
    Validate DBMS name for sqlmap --dbms option.

    Accepted examples:
    - mysql
    - postgresql
    - mssql
    """
    if not value or not isinstance(value, str):
        return False

    return value.strip().lower() in _SQL_DBMS


def validate_sql_techniques(value: str) -> bool:
    """
    Validate SQL injection techniques for sqlmap --technique.

    Allowed letters:
    B, E, U, S, T, Q

    Example:
    - BEUSTQ
    - TQ
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip().upper()
    return all(ch in _SQL_TECHNIQUES for ch in value)


def validate_sql_boolean_expression(value: str) -> bool:
    """
    Validate a basic SQL boolean or logical expression.

    Used for:
    - sqlmap filters
    - manual payload constraints

    Example:
    - id=1
    - 1=1
    - user='admin'
    """
    if not value or not isinstance(value, str):
        return False

    value = value.strip()
    return bool(_SQL_BOOLEAN_EXPR.match(value))


def validate_sql_level(value: str) -> bool:
    """
    Validate sqlmap --level option.

    Allowed range: 1–5
    """
    try:
        level = int(value)
        return 1 <= level <= 5
    except (ValueError, TypeError):
        return False


def validate_sql_risk(value: str) -> bool:
    """
    Validate sqlmap --risk option.

    Allowed range: 1–3
    """
    try:
        risk = int(value)
        return 1 <= risk <= 3
    except (ValueError, TypeError):
        return False
