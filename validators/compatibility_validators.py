"""
compatibility_validators.py
===========================

Validates service and flag compatibility, dependencies, and restrictions
based on YAML manifest definitions.

Handles:
- Service combination rules (can/cannot combine)
- Flag dependencies (requires, incompatible_with)
- Flag implications (implies - auto-enable flags)
- Flag overrides (overrides - remove conflicting flags)
- Privilege requirement checks
- Sub-option dependencies (parent flag requirements)
- Mutually exclusive flag groups

Each validator returns (is_valid, errors, warnings) tuples, where:
- is_valid: Boolean indicating if validation passed
- errors: List of error messages (blocking issues)
- warnings: List of warning messages (non-blocking issues)

Usage Example:
    from validators import compatibility_validators
    
    # Validate service and flag combinations
    is_valid, errors, warnings, updated_flags = (
        compatibility_validators.validate_all_compatibilities(
            selected_services=["service_1", "service_2"],
            selected_flags={"-cc": "cert.pem", "-ck": "key.pem"},
            manifest=manifest_dict
        )
    )
    
    if not is_valid:
        for error in errors:
            print(f"Error: {error}")
    
    if warnings:
        for warning in warnings:
            print(f"Warning: {warning}")
"""

import os
import sys
from typing import Dict, List, Tuple, Optional, Any
import logging

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Service Compatibility Validation
# ------------------------------------------------------------------------------

def validate_service_compatibility(
    selected_services: List[str],
    manifest: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    """
    Check if selected services can be combined based on manifest rules.
    
    Args:
        selected_services: List of service IDs that user wants to combine
        manifest: Full manifest dictionary containing service_restrictions
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
        - is_valid: True if all services are compatible
        - list_of_errors: List of error messages describing incompatibilities
    
    Example:
        manifest = {
            "service_restrictions": {
                "service_1": {
                    "incompatible_services": ["service_3", "service_5"],
                    "compatible_services": ["service_2", "service_4", "service_6"]
                }
            }
        }
        is_valid, errors = validate_service_compatibility(
            ["service_1", "service_3"], manifest
        )
    """
    errors = []
    restrictions = manifest.get("service_restrictions", {})
    
    if not selected_services:
        return True, []  # No services selected is valid
    
    # Check each service against all others
    for i, service_id in enumerate(selected_services):
        service_rules = restrictions.get(service_id, {})
        
        # Check incompatible services
        incompatible = service_rules.get("incompatible_services", [])
        for other_service in selected_services:
            if other_service != service_id and other_service in incompatible:
                errors.append(
                    f"Service '{service_id}' cannot be combined with '{other_service}'"
                )
        
        # Check privilege requirements (warning, not blocking)
        required_priv = service_rules.get("requires_privileges")
        if required_priv:
            has_priv, priv_error = check_privileges(required_priv)
            if not has_priv:
                errors.append(
                    f"Service '{service_id}' requires {required_priv} privileges: {priv_error}"
                )
        
        # Check required flags for service
        required_flags = service_rules.get("requires_flags", [])
        if required_flags:
            # This is informational - actual flag validation happens separately
            pass
    
    return len(errors) == 0, errors


def get_compatible_services(
    service_id: str,
    manifest: Dict[str, Any]
) -> Tuple[List[str], List[str]]:
    """
    Get list of compatible and incompatible services for a given service.
    
    Args:
        service_id: Service ID to check
        manifest: Full manifest dictionary
    
    Returns:
        Tuple[List[str], List[str]]: (compatible_services, incompatible_services)
    """
    restrictions = manifest.get("service_restrictions", {})
    service_rules = restrictions.get(service_id, {})
    
    compatible = service_rules.get("compatible_services", [])
    incompatible = service_rules.get("incompatible_services", [])
    
    return compatible, incompatible


# ------------------------------------------------------------------------------
# Flag Compatibility Validation
# ------------------------------------------------------------------------------

def validate_flag_compatibility(
    selected_flags: Dict[str, Any],
    flag_restrictions: Dict[str, Any]
) -> Tuple[bool, List[str], List[str]]:
    """
    Validate flag combinations based on restrictions.
    
    Args:
        selected_flags: Dictionary of flag -> value (True/False/string/number)
        flag_restrictions: Dictionary of flag -> restriction rules
    
    Returns:
        Tuple[bool, List[str], List[str]]: (is_valid, errors, warnings)
    
    Example:
        selected_flags = {"-cc": "cert.pem", "-ck": "key.pem", "-w": "wordlist.txt"}
        flag_restrictions = {
            "-cc": {"requires": ["-ck"]},
            "-ck": {"requires": ["-cc"]}
        }
    """
    errors = []
    warnings = []
    flags_copy = selected_flags.copy()
    
    # First pass: Check requirements and incompatibilities
    for flag, value in selected_flags.items():
        if value is None or value is False:
            continue  # Skip disabled flags
        
        rules = flag_restrictions.get(flag, {})
        
        # Check required flags
        requires = rules.get("requires", [])
        for req_flag in requires:
            if req_flag not in flags_copy or not flags_copy.get(req_flag):
                errors.append(
                    f"Flag '{flag}' requires '{req_flag}' to be set"
                )
        
        # Check incompatible flags
        incompatible = rules.get("incompatible_with", [])
        for inc_flag in incompatible:
            if inc_flag in flags_copy and flags_copy.get(inc_flag):
                errors.append(
                    f"Flag '{flag}' cannot be used with '{inc_flag}'"
                )
        
        # Check depends_on (parent flag requirement)
        depends_on = rules.get("depends_on")
        if depends_on:
            parent_id = depends_on.get("placeholder") or depends_on.get("flag")
            required_value = depends_on.get("value", True)
            if parent_id not in flags_copy:
                errors.append(
                    f"Flag '{flag}' requires parent flag '{parent_id}' to be set"
                )
            elif flags_copy[parent_id] != required_value:
                errors.append(
                    f"Flag '{flag}' requires '{parent_id}' to be '{required_value}'"
                )
        
        # Check sub-option parent requirement
        parent_flag = rules.get("requires_parent")
        if parent_flag:
            if parent_flag not in flags_copy or not flags_copy.get(parent_flag):
                errors.append(
                    f"Flag '{flag}' requires parent flag '{parent_flag}' to be set"
                )
    
    # Second pass: Handle implications (auto-enable)
    for flag, value in selected_flags.items():
        if value is None or value is False:
            continue
        
        rules = flag_restrictions.get(flag, {})
        implies = rules.get("implies", [])
        for imp_flag in implies:
            if imp_flag not in flags_copy:
                flags_copy[imp_flag] = True
                warnings.append(
                    f"Flag '{flag}' automatically enables '{imp_flag}'"
                )
    
    # Third pass: Handle overrides (remove conflicting)
    flags_to_remove = []
    for flag, value in flags_copy.items():
        if value is None or value is False:
            continue
        
        rules = flag_restrictions.get(flag, {})
        overrides = rules.get("overrides", [])
        for ovr_flag in overrides:
            if ovr_flag in flags_copy:
                flags_to_remove.append(ovr_flag)
                warnings.append(
                    f"Flag '{flag}' overrides '{ovr_flag}' (removed)"
                )
    
    # Remove overridden flags
    for flag_to_remove in flags_to_remove:
        if flag_to_remove in flags_copy:
            del flags_copy[flag_to_remove]
    
    return len(errors) == 0, errors, warnings


def apply_flag_implications(
    selected_flags: Dict[str, Any],
    flag_restrictions: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Apply flag implications (auto-enable implied flags).
    
    Args:
        selected_flags: Dictionary of flag -> value
        flag_restrictions: Dictionary of flag -> restriction rules
    
    Returns:
        Updated flags dictionary with implied flags enabled
    """
    flags_copy = selected_flags.copy()
    
    # Iterate until no new implications
    changed = True
    while changed:
        changed = False
        for flag, value in flags_copy.items():
            if value is None or value is False:
                continue
            
            rules = flag_restrictions.get(flag, {})
            implies = rules.get("implies", [])
            for imp_flag in implies:
                if imp_flag not in flags_copy:
                    flags_copy[imp_flag] = True
                    changed = True
    
    return flags_copy


def apply_flag_overrides(
    selected_flags: Dict[str, Any],
    flag_restrictions: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Apply flag overrides (remove conflicting flags).
    
    Args:
        selected_flags: Dictionary of flag -> value
        flag_restrictions: Dictionary of flag -> restriction rules
    
    Returns:
        Tuple[Dict[str, Any], List[str]]: (updated_flags, removed_flags_list)
    """
    flags_copy = selected_flags.copy()
    removed = []
    
    # Find all flags that should be overridden
    overridden_flags = set()
    for flag, value in flags_copy.items():
        if value is None or value is False:
            continue
        
        rules = flag_restrictions.get(flag, {})
        overrides = rules.get("overrides", [])
        overridden_flags.update(overrides)
    
    # Remove overridden flags
    for ovr_flag in overridden_flags:
        if ovr_flag in flags_copy:
            del flags_copy[ovr_flag]
            removed.append(ovr_flag)
    
    return flags_copy, removed


# ------------------------------------------------------------------------------
# Mutually Exclusive Flag Groups
# ------------------------------------------------------------------------------

def validate_mutually_exclusive_group(
    selected_flags: Dict[str, Any],
    exclusive_group: List[str],
    group_name: str = "flags"
) -> Tuple[bool, List[str]]:
    """
    Validate that at most one flag from a mutually exclusive group is selected.
    
    Args:
        selected_flags: Dictionary of flag -> value
        exclusive_group: List of flags that are mutually exclusive
        group_name: Name of the group for error messages
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    
    Example:
        # For flags: -u | --sctp (only one can be used)
        is_valid, errors = validate_mutually_exclusive_group(
            {"-u": True, "--sctp": True}, ["-u", "--sctp"], "transport protocol"
        )
    """
    errors = []
    selected_in_group = [
        flag for flag in exclusive_group
        if flag in selected_flags and selected_flags.get(flag)
    ]
    
    if len(selected_in_group) > 1:
        errors.append(
            f"Mutually exclusive {group_name}: {', '.join(selected_in_group)} "
            f"(only one can be selected)"
        )
    
    return len(errors) == 0, errors


def validate_mutually_exclusive_flags(
    selected_flags: Dict[str, Any],
    flag_restrictions: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    """
    Validate all mutually exclusive flag groups defined in restrictions.
    
    Args:
        selected_flags: Dictionary of flag -> value
        flag_restrictions: Dictionary containing mutually_exclusive_groups
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    # Check mutually_exclusive_groups in flag_restrictions
    exclusive_groups = flag_restrictions.get("mutually_exclusive_groups", [])
    for group in exclusive_groups:
        group_flags = group.get("flags", [])
        group_name = group.get("name", "flags")
        is_valid, group_errors = validate_mutually_exclusive_group(
            selected_flags, group_flags, group_name
        )
        errors.extend(group_errors)
    
    return len(errors) == 0, errors


# ------------------------------------------------------------------------------
# Privilege Checking
# ------------------------------------------------------------------------------

def check_privileges(required_level: str) -> Tuple[bool, str]:
    """
    Check if user has required privilege level.
    
    Args:
        required_level: "root", "admin", "administrator", or "user"
    
    Returns:
        Tuple[bool, str]: (has_privileges, error_message_if_not)
    """
    if required_level.lower() in ("root", "admin", "administrator"):
        # Check if running as root/administrator
        if sys.platform == "win32":
            # Windows: Check if running as administrator
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    return False, "Administrator privileges required"
            except Exception:
                return False, "Cannot determine administrator status"
        else:
            # Unix-like: Check if running as root
            if os.geteuid() != 0:
                return False, "Root privileges required"
    
    return True, ""


def validate_privilege_requirements(
    service_id: Optional[str],
    selected_flags: Dict[str, Any],
    manifest: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    """
    Check privilege requirements for services and flags.
    
    Args:
        service_id: Optional service ID
        selected_flags: Dictionary of selected flags
        manifest: Full manifest dictionary
    
    Returns:
        Tuple[bool, List[str]]: (has_privileges, list_of_warnings)
    """
    warnings = []
    
    # Check service-level privileges
    if service_id:
        restrictions = manifest.get("service_restrictions", {})
        service_rules = restrictions.get(service_id, {})
        required_priv = service_rules.get("requires_privileges")
        if required_priv:
            has_priv, error_msg = check_privileges(required_priv)
            if not has_priv:
                warnings.append(f"Service '{service_id}': {error_msg}")
    
    # Check flag-level privileges
    flag_restrictions = manifest.get("flag_restrictions", {})
    for flag, value in selected_flags.items():
        if value is None or value is False:
            continue
        
        rules = flag_restrictions.get(flag, {})
        required_priv = rules.get("requires_privileges")
        if required_priv:
            has_priv, error_msg = check_privileges(required_priv)
            if not has_priv:
                warnings.append(f"Flag '{flag}': {error_msg}")
    
    return len(warnings) == 0, warnings


# ------------------------------------------------------------------------------
# Sub-Option Dependencies
# ------------------------------------------------------------------------------

def validate_sub_option_dependencies(
    selected_flags: Dict[str, Any],
    flag_restrictions: Dict[str, Any],
    parent_flag: str
) -> Tuple[bool, List[str]]:
    """
    Validate that sub-options have their parent flag set.
    
    Args:
        selected_flags: Dictionary of flag -> value
        flag_restrictions: Dictionary of flag restrictions
        parent_flag: Parent flag that must be present
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    
    Example:
        # --ssl-verify requires --ssl
        validate_sub_option_dependencies(
            {"--ssl-verify": True}, flag_restrictions, "--ssl"
        )
    """
    errors = []
    
    # Check if parent flag is present
    parent_present = parent_flag in selected_flags and selected_flags.get(parent_flag)
    
    if not parent_present:
        # Find all sub-options that require this parent
        sub_options = []
        for flag, rules in flag_restrictions.items():
            if rules.get("requires_parent") == parent_flag:
                if flag in selected_flags and selected_flags.get(flag):
                    sub_options.append(flag)
        
        if sub_options:
            errors.append(
                f"Flags {', '.join(sub_options)} require parent flag '{parent_flag}' to be set"
            )
    
    return len(errors) == 0, errors


# ------------------------------------------------------------------------------
# Comprehensive Validation Function
# ------------------------------------------------------------------------------

def validate_all_compatibilities(
    selected_services: List[str],
    selected_flags: Dict[str, Any],
    manifest: Dict[str, Any]
) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
    """
    Comprehensive validation of services and flags compatibility.
    
    This function performs all compatibility checks:
    1. Service combination validation
    2. Flag compatibility validation
    3. Flag implications (auto-enable)
    4. Flag overrides (remove conflicting)
    5. Mutually exclusive flag validation
    6. Privilege requirement checks
    7. Sub-option dependencies
    
    Args:
        selected_services: List of service IDs
        selected_flags: Dictionary of flag -> value
        manifest: Full manifest dictionary
    
    Returns:
        Tuple[bool, List[str], List[str], Dict[str, Any]]:
        - is_valid: True if all validations pass
        - errors: List of error messages (blocking)
        - warnings: List of warning messages (non-blocking)
        - updated_flags: Flags dictionary with implications applied and overrides removed
    
    Example:
        is_valid, errors, warnings, updated_flags = validate_all_compatibilities(
            ["service_1", "service_2"],
            {"-cc": "cert.pem", "-ck": "key.pem"},
            manifest
        )
    """
    all_errors = []
    all_warnings = []
    
    # 1. Validate service compatibility
    is_valid, service_errors = validate_service_compatibility(selected_services, manifest)
    all_errors.extend(service_errors)
    
    # 2. Apply flag implications first
    flag_restrictions = manifest.get("flag_restrictions", {})
    flags_copy = apply_flag_implications(selected_flags, flag_restrictions)
    
    # 3. Apply flag overrides
    flags_copy, removed_flags = apply_flag_overrides(flags_copy, flag_restrictions)
    if removed_flags:
        all_warnings.extend([
            f"Flag override: Removed {flag} due to conflicting flag"
            for flag in removed_flags
        ])
    
    # 4. Validate flag compatibility (after implications and overrides)
    is_valid, flag_errors, flag_warnings = validate_flag_compatibility(
        flags_copy, flag_restrictions
    )
    all_errors.extend(flag_errors)
    all_warnings.extend(flag_warnings)
    
    # 5. Validate mutually exclusive flags
    is_valid, mutex_errors = validate_mutually_exclusive_flags(
        flags_copy, flag_restrictions
    )
    all_errors.extend(mutex_errors)
    
    # 6. Check privilege requirements (warnings only)
    has_priv, priv_warnings = validate_privilege_requirements(
        selected_services[0] if selected_services else None,
        flags_copy,
        manifest
    )
    all_warnings.extend(priv_warnings)
    
    # 7. Validate sub-option dependencies for common parent flags
    common_parents = ["--proxy", "--ssl", "--tcp", "--udp", "--icmp"]
    for parent in common_parents:
        is_valid, sub_errors = validate_sub_option_dependencies(
            flags_copy, flag_restrictions, parent
        )
        all_errors.extend(sub_errors)
    
    return len(all_errors) == 0, all_errors, all_warnings, flags_copy


# ------------------------------------------------------------------------------
# Helper Functions for Common Patterns
# ------------------------------------------------------------------------------

def check_flag_group_compatibility(
    selected_flags: Dict[str, Any],
    groups: List[Dict[str, Any]]
) -> Tuple[bool, List[str]]:
    """
    Check compatibility between flag groups (e.g., transport protocols).
    
    Args:
        selected_flags: Dictionary of flag -> value
        groups: List of group definitions with 'flags' and 'name' keys
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    for group in groups:
        group_flags = group.get("flags", [])
        group_name = group.get("name", "flags")
        
        selected_in_group = [
            flag for flag in group_flags
            if flag in selected_flags and selected_flags.get(flag)
        ]
        
        if len(selected_in_group) > 1:
            errors.append(
                f"Multiple {group_name} selected: {', '.join(selected_in_group)} "
                f"(only one allowed)"
            )
        
        # Check cross-group incompatibilities
        incompatible_groups = group.get("incompatible_groups", [])
        for inc_group_name in incompatible_groups:
            # Find flags from incompatible group
            for other_group in groups:
                if other_group.get("name") == inc_group_name:
                    other_group_flags = other_group.get("flags", [])
                    selected_in_other = [
                        flag for flag in other_group_flags
                        if flag in selected_flags and selected_flags.get(flag)
                    ]
                    if selected_in_group and selected_in_other:
                        errors.append(
                            f"{group_name} flags {', '.join(selected_in_group)} "
                            f"cannot be combined with {inc_group_name} flags "
                            f"{', '.join(selected_in_other)}"
                        )
    
    return len(errors) == 0, errors

