# Required Validators Analysis

Based on review of all 10 update instruction files, here are the validators needed:

## Existing Validators (Already Implemented)

### network_validators.py
- ✅ validate_ip, validate_ipv4, validate_ipv6
- ✅ validate_cidr
- ✅ validate_hostname
- ✅ validate_port, validate_port_optional
- ✅ validate_host_and_port, validate_hostport_or_port
- ✅ validate_url
- ✅ validate_host_or_path (for Unix sockets)

### file_validators.py
- ✅ validate_file_exists
- ✅ validate_file_readable
- ✅ validate_file_extension
- ✅ validate_directory_exists
- ✅ validate_writable_directory

### input_validators.py
- ✅ validate_integer
- ✅ validate_float
- ✅ validate_port_range (basic)
- ✅ validate_ip_or_range
- ✅ validate_non_empty

---

## NEW Validators Needed

### 1. time_validators.py (NEW FILE)
**Purpose**: Validate time formats used across multiple tools

**Functions Needed**:
```python
def validate_time_format(value: str) -> bool:
    """
    Validate time format: number + optional unit (ms, s, m, h)
    Examples: "500ms", "30s", "2m", "0.5h", "10"
    """
    
def validate_time_range(value: str) -> bool:
    """
    Validate time range format: "0.1-2.0" (used by ffuf -p)
    """

def validate_delay_format(value: str) -> bool:
    """
    Validate delay format (can be time or range)
    """
```

**Used by**:
- **nmap**: --scan-delay, --host-timeout, --min-rtt-timeout, etc.
- **nping**: --delay (time format)
- **ncat**: -w, -i, -d (time formats)
- **ffuf**: -p (delay range: "0.1" or "0.1-2.0"), -timeout
- **masscan**: --wait, --retries
- **sqlmap**: (implicit timeouts)

---

### 2. port_validators.py (ENHANCE EXISTING)
**Purpose**: Enhanced port specification validation

**New Functions Needed**:
```python
def validate_nmap_port_spec(value: str) -> bool:
    """
    Validate complex nmap port specification:
    Examples: "22", "1-65535", "U:53,111,137,T:21-25,80,139,8080,S:9"
    Supports: U: (UDP), T: (TCP), S: (SCTP) prefixes
    """
    
def validate_port_ratio(value: str) -> bool:
    """
    Validate port ratio (decimal 0.0-1.0)
    Example: "0.5"
    """

def validate_port_count(value: str, max_value: int = 65535) -> bool:
    """
    Validate port count for --top-ports
    """
```

**Used by**:
- **nmap**: -p (complex port specs), --top-ports, --port-ratio
- **ncat/nping**: -p (port spec)
- **masscan**: -p/--ports (port ranges)

---

### 3. protocol_validators.py (NEW FILE)
**Purpose**: Validate protocol-specific inputs

**Functions Needed**:
```python
def validate_tcp_flags(value: str) -> bool:
    """
    Validate TCP flag combinations
    Examples: "SYN", "ACK,PSH", "SYN,ACK,RST,FIN"
    Valid flags: SYN, ACK, FIN, RST, PSH, URG
    """

def validate_icmp_type(value: str) -> bool:
    """
    Validate ICMP type (0-255)
    """

def validate_icmp_code(value: str, icmp_type: str = None) -> bool:
    """
    Validate ICMP code (0-255)
    Optionally validate against ICMP type
    """

def validate_arp_type(value: str) -> bool:
    """
    Validate ARP type: "ARP", "ARP-reply", "RARP", "RARP-reply"
    Or numeric: 1, 2, 3, 4
    """

def validate_ip_protocol(value: str) -> bool:
    """
    Validate IP protocol number (0-255)
    Or protocol name: "tcp", "udp", "icmp"
    """

def validate_ether_type(value: str) -> bool:
    """
    Validate EtherType (hex: 0x0800, or decimal)
    """
```

**Used by**:
- **nmap**: --scanflags, -PO (IP protocol)
- **nping**: --flags, --icmp-type, --icmp-code, --arp-type, --ether-type
- **ncat**: (TCP flags implicit)

---

### 4. mac_validators.py (NEW FILE)
**Purpose**: Validate MAC addresses

**Functions Needed**:
```python
def validate_mac_address(value: str) -> bool:
    """
    Validate MAC address formats:
    - 00:11:22:33:44:55 (colon-separated)
    - 00-11-22-33-44-55 (hyphen-separated)
    - 001122334455 (no separator)
    """

def validate_mac_vendor(value: str) -> bool:
    """
    Validate MAC vendor name (for --spoof-mac)
    Examples: "Apple", "Cisco"
    (Could use lookup table or allow any string)
    """
```

**Used by**:
- **nmap**: --spoof-mac
- **masscan**: --adapter-mac, --router-mac
- **nping**: --source-mac, --dest-mac, --arp-sender-mac, --arp-target-mac

---

### 5. url_validators.py (ENHANCE EXISTING)
**Purpose**: Enhanced URL and proxy validation

**New Functions Needed**:
```python
def validate_proxy_url(value: str) -> bool:
    """
    Validate proxy URL formats:
    - http://127.0.0.1:8080
    - socks5://127.0.0.1:8080
    - socks4://127.0.0.1:8080
    """

def validate_socks_proxy(value: str) -> bool:
    """
    Specific validation for SOCKS proxies
    """

def validate_http_proxy(value: str) -> bool:
    """
    Specific validation for HTTP proxies
    """

def validate_proxy_auth(value: str) -> bool:
    """
    Validate proxy authentication: "user:pass"
    """
```

**Used by**:
- **ffuf**: -x (proxy URL), -replay-proxy
- **ncat**: --proxy (proxy URL)
- **sqlmap**: --proxy
- **nmap**: --proxies

---

### 6. ssl_validators.py (NEW FILE)
**Purpose**: SSL/TLS certificate and configuration validation

**Functions Needed**:
```python
def validate_pem_file(value: str) -> bool:
    """
    Validate PEM certificate/key file
    Check file exists and has .pem extension (or common cert extensions)
    """

def validate_ssl_cipher_list(value: str) -> bool:
    """
    Validate SSL cipher list syntax
    (Complex - could be basic format check)
    """

def validate_alpn_protocols(value: str) -> bool:
    """
    Validate ALPN protocol list (comma-separated)
    Example: "h2,http/1.1"
    """

def validate_sni(value: str) -> bool:
    """
    Validate Server Name Indication (hostname format)
    """
```

**Used by**:
- **ncat**: --ssl-cert, --ssl-key, --ssl-trustfile, --ssl-ciphers, --ssl-alpn, --ssl-servername
- **ffuf**: -sni

---

### 7. sql_validators.py (NEW FILE)
**Purpose**: SQL injection and database-related validation

**Functions Needed**:
```python
def validate_sql_technique(value: str) -> bool:
    """
    Validate SQL injection techniques: B, E, U, S, T, Q
    Examples: "BEUSTQ", "B", "E,U"
    """

def validate_dbms_name(value: str) -> bool:
    """
    Validate DBMS name
    Common: MySQL, PostgreSQL, Oracle, MSSQL, etc.
    (Could use enum or allow any string)
    """

def validate_database_name(value: str) -> bool:
    """
    Validate SQL database name (identifier rules)
    """

def validate_table_name(value: str) -> bool:
    """
    Validate SQL table name (identifier rules)
    """

def validate_column_name(value: str) -> bool:
    """
    Validate SQL column name (identifier rules)
    """

def validate_sql_level(value: str) -> bool:
    """
    Validate level (1-5) for sqlmap --level
    """

def validate_sql_risk(value: str) -> bool:
    """
    Validate risk level (1-3) for sqlmap --risk
    """
```

**Used by**:
- **sqlmap**: --technique, --dbms, -D, -T, -C, --level, --risk

---

### 8. http_validators.py (NEW FILE)
**Purpose**: HTTP-specific validation

**Functions Needed**:
```python
def validate_http_method(value: str) -> bool:
    """
    Validate HTTP method: GET, POST, PUT, DELETE, HEAD, OPTIONS, etc.
    """

def validate_http_header(value: str) -> bool:
    """
    Validate HTTP header format: "Name: Value"
    """

def validate_http_status_code(value: str) -> bool:
    """
    Validate HTTP status code or range
    Examples: "200", "200-299", "all", "200,301,404"
    """

def validate_content_type(value: str) -> bool:
    """
    Validate Content-Type header value
    Example: "application/json"
    """

def validate_url_with_fuzz(value: str) -> bool:
    """
    Validate URL that should contain FUZZ keyword (ffuf)
    """
```

**Used by**:
- **ffuf**: -X (HTTP method), -H (headers), -mc (status codes)
- **sqlmap**: --data (POST data), --cookie

---

### 9. target_validators.py (NEW FILE)
**Purpose**: Complex target specification validation

**Functions Needed**:
```python
def validate_nmap_target(value: str) -> bool:
    """
    Validate nmap target specification:
    - Single: "192.168.1.1"
    - CIDR: "192.168.0.0/24"
    - Range: "192.168.0-255.1-254"
    - Multiple: "192.168.1.1,10.0.0.1"
    - Hostname: "scanme.nmap.org"
    """

def validate_target_list(value: str) -> bool:
    """
    Validate comma-separated target list
    """

def validate_target_count(value: str) -> bool:
    """
    Validate target count for -iR (random targets)
    """
```

**Used by**:
- **nmap**: target specification, -iR
- **nping**: target specification, -iR
- **masscan**: target specification

---

### 10. dns_validators.py (NEW FILE)
**Purpose**: DNS-related validation

**Functions Needed**:
```python
def validate_dns_servers(value: str) -> bool:
    """
    Validate comma-separated DNS server list
    Example: "8.8.8.8,1.1.1.1"
    """

def validate_asn(value: str) -> bool:
    """
    Validate Autonomous System Number
    Formats: "AS12345" or "12345"
    """
```

**Used by**:
- **nmap**: --dns-servers
- **whois**: ASN queries (AS<number>)

---

### 11. rate_validators.py (NEW FILE)
**Purpose**: Rate and performance-related validation

**Functions Needed**:
```python
def validate_packet_rate(value: str) -> bool:
    """
    Validate packets per second rate
    Examples: "100", "1000", "10000"
    """

def validate_thread_count(value: str, max_value: int = None) -> bool:
    """
    Validate thread/concurrency count
    """

def validate_timing_template(value: str) -> bool:
    """
    Validate timing template: 0-5 (nmap -T)
    """
```

**Used by**:
- **nmap**: --min-rate, --max-rate, -T (timing template)
- **masscan**: --rate
- **ffuf**: --rate, -t (threads)
- **nping**: --rate

---

### 12. ffuf_validators.py (NEW FILE - Tool-specific)
**Purpose**: FFUF-specific validation rules

**Functions Needed**:
```python
def validate_fuzz_keyword(value: str) -> bool:
    """
    Check if FUZZ or KEYWORD exists in string
    """

def validate_encoder_spec(value: str) -> bool:
    """
    Validate encoder specification: 'FUZZ:urlencode b64encode'
    """

def validate_extension_list(value: str) -> bool:
    """
    Validate comma-separated extension list
    Example: "php,html,js"
    """

def validate_match_filter_value(value: str) -> bool:
    """
    Validate match/filter values (can be ranges, comparisons)
    Examples: ">100", "<100", "200-299", "42"
    """

def validate_ffuf_mode(value: str) -> bool:
    """
    Validate ffuf mode: "clusterbomb", "pitchfork", "sniper"
    """

def validate_ffuf_format(value: str) -> bool:
    """
    Validate output format: "json", "ejson", "html", "md", "csv", "ecsv", "all"
    """
```

**Used by**:
- **ffuf**: All services

---

### 13. whois_validators.py (NEW FILE - Tool-specific)
**Purpose**: WHOIS-specific validation

**Functions Needed**:
```python
def validate_whois_query_type(value: str) -> bool:
    """
    Validate query type for -q: "version", "sources", "types"
    """

def validate_whois_type_list(value: str) -> bool:
    """
    Validate WHOIS object type list for -T
    Example: "inetnum,route"
    """

def validate_whois_source_list(value: str) -> bool:
    """
    Validate source list for -s
    """
```

**Used by**:
- **whois**: All services

---

### 14. compatibility_validators.py (NEW FILE)
**Purpose**: Service and flag compatibility validation

**Functions Needed**:
```python
def validate_service_compatibility(selected_services: List[str], manifest: dict) -> Tuple[bool, List[str]]:
    """
    Check if selected services can be combined
    Returns: (is_valid, list_of_errors)
    """

def validate_flag_dependencies(selected_flags: dict, flag_restrictions: dict) -> Tuple[bool, List[str]]:
    """
    Validate flag dependencies (requires, incompatible_with, etc.)
    Returns: (is_valid, list_of_errors)
    """

def validate_privilege_requirements(service_id: str, flags: dict, manifest: dict) -> Tuple[bool, str]:
    """
    Check if user has required privileges for service/flags
    Returns: (has_privileges, error_message)
    """

def check_flag_implies(selected_flags: dict, flag_restrictions: dict) -> dict:
    """
    Auto-enable implied flags (e.g., -acc implies -ac)
    Returns: updated flags dict
    """

def check_flag_overrides(selected_flags: dict, flag_restrictions: dict) -> dict:
    """
    Remove overridden flags (e.g., -input-cmd overrides -w)
    Returns: updated flags dict
    """
```

**Used by**:
- **All tools**: Service/flag compatibility checks

---

### 15. format_validators.py (NEW FILE)
**Purpose**: Output format and encoding validation

**Functions Needed**:
```python
def validate_output_format(value: str, allowed_formats: List[str]) -> bool:
    """
    Validate output format against allowed list
    """

def validate_encoding(value: str) -> bool:
    """
    Validate encoding name (e.g., "urlencode", "b64encode")
    """

def validate_regex(value: str) -> bool:
    """
    Basic regex pattern validation (syntax check)
    """
```

**Used by**:
- **ffuf**: -of, -enc, -fr, -mr
- **nmap**: -oN, -oX, -oS, -oG, -oA

---

## Summary of Required New Validator Files

1. ✅ **time_validators.py** - Time format validation (ms, s, m, h, ranges)
2. ✅ **port_validators.py** - Enhanced port specification (complex nmap formats)
3. ✅ **protocol_validators.py** - TCP flags, ICMP types, ARP types, IP protocols
4. ✅ **mac_validators.py** - MAC address validation
5. ✅ **url_validators.py** - Enhanced URL/proxy validation (extend existing)
6. ✅ **ssl_validators.py** - SSL/TLS certificate and config validation
7. ✅ **sql_validators.py** - SQL injection and database validation
8. ✅ **http_validators.py** - HTTP method, headers, status codes
9. ✅ **target_validators.py** - Complex target specification validation
10. ✅ **dns_validators.py** - DNS servers, ASN validation
11. ✅ **rate_validators.py** - Rate, threads, timing validation
12. ✅ **ffuf_validators.py** - FFUF-specific validation (optional - could be in tool adapter)
13. ✅ **whois_validators.py** - WHOIS-specific validation (optional - could be in tool adapter)
14. ✅ **compatibility_validators.py** - Service/flag compatibility validation (CRITICAL)
15. ✅ **format_validators.py** - Output format and encoding validation

## Priority Order

**HIGH PRIORITY** (Required for basic functionality):
1. compatibility_validators.py - Service/flag compatibility
2. time_validators.py - Used by multiple tools
3. port_validators.py - Enhanced port specs
4. protocol_validators.py - TCP/ICMP/ARP validation
5. target_validators.py - Complex target specs

**MEDIUM PRIORITY** (Tool-specific but important):
6. mac_validators.py
7. url_validators.py (enhance existing)
8. ssl_validators.py
9. sql_validators.py
10. http_validators.py
11. rate_validators.py

**LOW PRIORITY** (Can be in tool adapters):
12. ffuf_validators.py
13. whois_validators.py
14. format_validators.py
15. dns_validators.py

