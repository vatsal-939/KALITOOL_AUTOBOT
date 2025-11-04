"""
interaction.py
===============
Handles all user interactions for KaliTool AutoBot.

Responsibilities:
    - Dynamically ask users questions based on YAML flags
    - Validate responses (IP, port, file path, etc.)
    - Return dictionary of chosen flags and values for command generation
"""

import re

class UserInteraction:
    """
    This class interacts with the user based on manifest data.
    Each flag entry in the manifest determines what kind of input to ask.
    """

    def __init__(self, validator=None):
        """
        :param validator: Optional validator object (e.g. NetworkValidator)
        """
        self.validator = validator

    # ----------------------------------------------------------------------
    def _ask_yes_no(self, question: str) -> bool:
        """Simple yes/no prompt."""
        while True:
            response = input(f"{question} (y/n): ").strip().lower()
            if response in ["y", "yes"]:
                return True
            elif response in ["n", "no"]:
                return False
            else:
                print("[!] Please answer with 'y' or 'n'.")

    # ----------------------------------------------------------------------
    def _ask_for_value(self, flag_name: str, description: str) -> str:
        """Ask the user for a value for a given flag."""
        value = input(f"Enter value for {flag_name} ({description}): ").strip()
        return value

    # ----------------------------------------------------------------------
    def collect_user_inputs(self, manifest_data: dict) -> dict:
        """
        Collect user input for the flags defined in manifest_data.
        Returns dictionary like:
            {
                "-p": "80",
                "-l": True,
                "--ssl": True
            }
        """
        if not manifest_data:
            raise ValueError("Manifest data is empty or None")
        
        print("\n[+] Configuring tool:", manifest_data.get("tool", manifest_data.get("tool_id", "Unknown")))
        print(f"    Command: {manifest_data.get('command', manifest_data.get('command_id', ''))}")
        print(f"    Description: {manifest_data.get('description', '')}\n")

        user_choices = {}

        # Check if this is the new services-based format
        if "services" in manifest_data:
            # New format: use services/placeholders structure
            print("[!] This manifest uses the new services-based format.")
            print("[!] The current interaction system expects a simple flags format.")
            print("[!] Please use the tool adapter for this command.")
            raise NotImplementedError(
                "Services-based manifests require tool adapters. "
                "This manifest format is not yet supported by the basic interaction system."
            )
        
        # Get flags - handle both list and dict formats, and None
        flags = manifest_data.get("flags")
        if flags is None:
            print("[!] Warning: No 'flags' found in manifest. Returning empty choices.")
            return {}
        elif isinstance(flags, dict):
            # Convert dict format to list format if needed
            flags = [{"flag": k, **v} if isinstance(v, dict) else {"flag": k, "description": str(v)} 
                     for k, v in flags.items()]
        elif not isinstance(flags, list):
            print(f"[!] Warning: 'flags' is not a list or dict (got {type(flags)}). Returning empty choices.")
            return {}

        # Each flag entry should have: flag, description, requires_value, category
        for flag_entry in flags:
            flag = flag_entry.get("flag")
            desc = flag_entry.get("description", "")
            requires_value = flag_entry.get("requires_value", False)

            print(f"\nFlag: {flag}")
            print(f"  ↳ {desc}")

            use_flag = self._ask_yes_no(f"Do you want to use {flag}?")

            if not use_flag:
                continue

            if requires_value:
                # Ask user for a value
                value = self._ask_for_value(flag, desc)

                # Optional: basic validation examples
                if "port" in desc.lower() and self.validator:
                    if not self.validator.validate_port(value):
                        print(f"[!] Invalid port number: {value}")
                        continue

                if "ip" in desc.lower() and self.validator:
                    if not self.validator.validate_ip(value):
                        print(f"[!] Invalid IP address: {value}")
                        continue

                user_choices[flag] = value
            else:
                # Boolean flag, just enable it
                user_choices[flag] = True

        return user_choices

    # ----------------------------------------------------------------------
    def confirm_command(self, full_command: str) -> bool:
        """Display the final command and confirm execution."""
        print("\n[COMMAND GENERATED]")
        print(f"  → {full_command}")
        return self._ask_yes_no("Do you want to execute this command now?")
