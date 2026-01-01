"""
port_validators.py
==================

Enhanced port specification validators for complex port specifications:
- validate_nmap_port_spec: Validate complex nmap port specifications with protocol prefixes
- validate_port_ratio: Validate port ratio (decimal 0.0-1.0)
- validate_port_count: Validate port count for --top-ports

Each validator raises ValueError with a helpful message if validation fails,
otherwise returns True.

Used by:
- nmap: -p (complex port specs), --top-ports, --port-ratio
- ncat/nping: -p (port spec)
- masscan: -p/--ports (port ranges)
"""

import re
from typing import Optional

# Port number: 1-65535
_PORT_RE = re.compile(r'^(\d{1,5})$')
_PORT_RANGE_RE = re.compile(r'^(\d{1,5})-(\d{1,5})$')

# Protocol prefix: U:, T:, S: (case-insensitive)
_PROTOCOL_PREFIX_RE = re.compile(r'^([UTS]):', re.IGNORECASE)

# Port specification parts: port number, range, or protocol:port(s)
_PORT_SPEC_PART_RE = re.compile(
    r'^([UTS]:)?'  # Optional protocol prefix (U:, T:, S:)
    r'(\d{1,5}(?:-\d{1,5})?)'  # Port number or range
    r'(?:,(\d{1,5}(?:-\d{1,5})?))*$',  # Optional comma-separated additional ports
    re.IGNORECASE
)


def _validate_single_port(port_str: str) -> bool:
    """
    Validate a single port number (1-65535).
    
    Args:
        port_str: Port number as string
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If port is invalid
    """
    if not port_str.isdigit():
        raise ValueError(f"Invalid port number: '{port_str}' (must be numeric)")
    
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError(
            f"Invalid port number: '{port_str}'. Port must be between 1 and 65535"
        )
    
    return True


def _validate_port_range(range_str: str) -> bool:
    """
    Validate a port range (e.g., "1-65535").
    
    Args:
        range_str: Port range as string (e.g., "1-65535")
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If range is invalid
    """
    match = _PORT_RANGE_RE.match(range_str)
    if not match:
        raise ValueError(
            f"Invalid port range format: '{range_str}'. Expected format: min-max (e.g., '1-65535')"
        )
    
    min_port_str, max_port_str = match.groups()
    min_port = int(min_port_str)
    max_port = int(max_port_str)
    
    # Validate individual ports
    _validate_single_port(min_port_str)
    _validate_single_port(max_port_str)
    
    # Validate range order
    if min_port > max_port:
        raise ValueError(
            f"Invalid port range: '{range_str}'. Minimum port ({min_port}) "
            f"cannot be greater than maximum port ({max_port})"
        )
    
    return True


def validate_nmap_port_spec(value: str) -> bool:
    """
    Validate complex nmap port specification.
    
    Supports:
    - Single ports: "22", "80", "443"
    - Port ranges: "1-65535", "1024-2048"
    - Protocol prefixes: "U:53", "T:80", "S:9"
    - Comma-separated lists: "22,80,443", "1-1024,8080-8090"
    - Protocol-prefixed lists: "U:53,111,137", "T:21-25,80,139,8080"
    - Mixed protocol specifications: "U:53,111,137,T:21-25,80,139,8080,S:9"
    
    Protocol prefixes:
    - U: or u: - UDP ports
    - T: or t: - TCP ports
    - S: or s: - SCTP ports
    
    Examples:
        "22"                    -> Valid (single TCP port)
        "1-65535"               -> Valid (all ports)
        "U:53,111,137"          -> Valid (UDP ports)
        "T:21-25,80,139,8080"   -> Valid (TCP ports and ranges)
        "U:53,111,137,T:21-25,80,139,8080,S:9" -> Valid (mixed protocols)
        "22,80,443"             -> Valid (comma-separated, default TCP)
        "1-1024,8080-8090"      -> Valid (multiple ranges)
    
    Args:
        value: Port specification string to validate
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If format is invalid
        
    Examples:
        >>> validate_nmap_port_spec("22")
        True
        >>> validate_nmap_port_spec("1-65535")
        True
        >>> validate_nmap_port_spec("U:53,111,137,T:21-25,80")
        True
        >>> validate_nmap_port_spec("invalid")
        Traceback (most recent call last):
        ValueError: Invalid nmap port specification: 'invalid'
    """
    if not value or not isinstance(value, str):
        raise ValueError(
            f"Invalid nmap port specification: '{value}'. "
            f"Expected port number, range, or protocol-prefixed specification"
        )
    
    value = value.strip()
    
    if not value:
        raise ValueError("Port specification cannot be empty")
    
    # Split by comma to handle multiple protocol groups and port lists
    # But we need to be careful because protocol prefixes apply to following ports
    # Format: [PROTO:]port[,port...][,PROTO:]port[,port...]
    
    # Strategy: Split by protocol prefixes first, then validate each group
    parts = []
    current_protocol = None
    current_ports = []
    
    # Split by protocol prefixes (U:, T:, S:)
    # This regex finds protocol prefixes and everything after them until next prefix or end
    protocol_sections = re.split(r'([UTS]:)', value, flags=re.IGNORECASE)
    
    i = 0
    while i < len(protocol_sections):
        section = protocol_sections[i].strip()
        
        if not section:
            i += 1
            continue
        
        # Check if this is a protocol prefix
        proto_match = _PROTOCOL_PREFIX_RE.match(section)
        if proto_match:
            # If we have accumulated ports, save them with previous protocol
            if current_ports:
                parts.append((current_protocol, ','.join(current_ports)))
                current_ports = []
            
            # Set new protocol
            current_protocol = proto_match.group(1).upper()
            # Get the ports after the protocol prefix
            if i + 1 < len(protocol_sections):
                current_ports = [protocol_sections[i + 1].strip()]
                i += 2
            else:
                raise ValueError(
                    f"Invalid nmap port specification: '{value}'. "
                    f"Protocol prefix '{section}' must be followed by port specification"
                )
        else:
            # This is a port specification (no protocol prefix = default TCP)
            if current_protocol is None:
                # No protocol set yet, this is default TCP
                current_protocol = 'T'  # Default to TCP
                current_ports.append(section)
            else:
                # Continue with current protocol
                current_ports.append(section)
            i += 1
    
    # Save last accumulated ports
    if current_ports:
        parts.append((current_protocol, ','.join(current_ports)))
    
    # If no protocol prefixes found, treat entire string as default TCP
    if not parts:
        parts = [('T', value)]
    
    # Validate each protocol group
    for protocol, port_spec in parts:
        # Split port spec by comma
        port_items = [p.strip() for p in port_spec.split(',') if p.strip()]
        
        if not port_items:
            raise ValueError(
                f"Invalid nmap port specification: '{value}'. "
                f"Protocol '{protocol}:' must have at least one port"
            )
        
        # Validate each port item (single port or range)
        for port_item in port_items:
            # Check if it's a range
            if '-' in port_item:
                _validate_port_range(port_item)
            else:
                _validate_single_port(port_item)
    
    return True


def validate_port_ratio(value: str) -> bool:
    """
    Validate port ratio (decimal 0.0-1.0).
    
    Used by nmap --port-ratio option to scan ports more common than the given ratio.
    
    Accepts:
    - Decimal numbers between 0.0 and 1.0 (inclusive)
    - Can be integer (0, 1) or float (0.0, 0.5, 1.0, etc.)
    
    Examples:
        "0.0"  -> Valid (scan all ports)
        "0.5"  -> Valid (scan ports more common than 50%)
        "1.0"  -> Valid (scan only most common ports)
        "0.25" -> Valid (scan ports more common than 25%)
    
    Args:
        value: Port ratio string to validate
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If ratio is invalid
        
    Examples:
        >>> validate_port_ratio("0.5")
        True
        >>> validate_port_ratio("0.0")
        True
        >>> validate_port_ratio("1.5")
        Traceback (most recent call last):
        ValueError: Invalid port ratio: '1.5'. Ratio must be between 0.0 and 1.0
    """
    if not value or not isinstance(value, str):
        raise ValueError(
            f"Invalid port ratio: '{value}'. Expected decimal number between 0.0 and 1.0"
        )
    
    value = value.strip()
    
    # Try to parse as float
    try:
        ratio = float(value)
    except ValueError:
        raise ValueError(
            f"Invalid port ratio: '{value}'. Expected decimal number (e.g., '0.5', '0.0', '1.0')"
        )
    
    # Validate range
    if not (0.0 <= ratio <= 1.0):
        raise ValueError(
            f"Invalid port ratio: '{value}'. Ratio must be between 0.0 and 1.0 (inclusive)"
        )
    
    return True


def validate_port_count(value: str, max_value: int = 65535) -> bool:
    """
    Validate port count for --top-ports option.
    
    Used by nmap --top-ports to scan the N most common ports.
    
    Accepts:
    - Positive integer
    - Must be between 1 and max_value (default 65535)
    
    Examples:
        "10"    -> Valid (top 10 ports)
        "100"   -> Valid (top 100 ports)
        "1000"  -> Valid (top 1000 ports)
        "65535" -> Valid (all ports, if max_value allows)
    
    Args:
        value: Port count string to validate
        max_value: Maximum allowed port count (default: 65535)
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If count is invalid
        
    Examples:
        >>> validate_port_count("10")
        True
        >>> validate_port_count("100")
        True
        >>> validate_port_count("0")
        Traceback (most recent call last):
        ValueError: Invalid port count: '0'. Count must be between 1 and 65535
    """
    if not value or not isinstance(value, str):
        raise ValueError(
            f"Invalid port count: '{value}'. Expected positive integer between 1 and {max_value}"
        )
    
    value = value.strip()
    
    # Check if it's a valid integer
    if not value.isdigit():
        raise ValueError(
            f"Invalid port count: '{value}'. Expected positive integer (e.g., '10', '100', '1000')"
        )
    
    count = int(value)
    
    # Validate range
    if count < 1:
        raise ValueError(
            f"Invalid port count: '{value}'. Count must be at least 1"
        )
    
    if count > max_value:
        raise ValueError(
            f"Invalid port count: '{value}'. Count cannot exceed {max_value} (got {count})"
        )
    
    return True


def validate_port_list(value: str) -> bool:
    """
    Validate comma-separated port list (simple format, no protocol prefixes).
    
    This is a simpler validator for tools that don't support protocol prefixes.
    Used by masscan, ncat, nping for basic port specifications.
    
    Accepts:
    - Single ports: "22", "80", "443"
    - Port ranges: "1-65535", "1024-2048"
    - Comma-separated: "22,80,443", "1-1024,8080-8090"
    - Mixed: "22,80-90,443,8080-8090"
    
    Examples:
        "22"              -> Valid
        "1-65535"         -> Valid
        "22,80,443"       -> Valid
        "1-1024,8080-8090" -> Valid
        "22,80-90,443"    -> Valid
    
    Args:
        value: Port list string to validate
        
    Returns:
        bool: True if valid
        
    Raises:
        ValueError: If format is invalid
    """
    if not value or not isinstance(value, str):
        raise ValueError(
            f"Invalid port list: '{value}'. Expected port number, range, or comma-separated list"
        )
    
    value = value.strip()
    
    if not value:
        raise ValueError("Port list cannot be empty")
    
    # Split by comma
    port_items = [p.strip() for p in value.split(',') if p.strip()]
    
    if not port_items:
        raise ValueError("Port list must contain at least one port")
    
    # Validate each item
    for port_item in port_items:
        if '-' in port_item:
            _validate_port_range(port_item)
        else:
            _validate_single_port(port_item)
    
    return True

