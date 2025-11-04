"""
command_builder.py
===================
Responsible for constructing the final command string
based on user inputs and tool metadata from YAML files.
"""

import shlex


class CommandBuilder:
    """
    Builds a full CLI command string from manifest data and user input.
    Example:
        Input:
            base_command: "ncat"
            user_flags: {"-l": True, "-p": "8080", "--ssl": True}
        Output:
            "ncat -l -p 8080 --ssl"
    """

    def __init__(self, base_command: str, user_flags: dict):
        """
        :param base_command: The root command name (e.g., 'ncat', 'nmap', etc.)
        :param user_flags: Dictionary of flags with values or True/False
        """
        self.base_command = base_command.strip()
        self.user_flags = user_flags or {}

    # ----------------------------------------------------------------------
    def build(self) -> str:
        """
        Construct the final command string using all provided flags and values.
        """
        if not self.base_command:
            raise ValueError("Base command cannot be empty.")

        command_parts = [self.base_command]

        for flag, value in self.user_flags.items():
            if isinstance(value, bool):
                # Boolean flag (e.g., -l)
                if value:
                    command_parts.append(flag)
            elif isinstance(value, (int, float, str)):
                # Flag with argument (e.g., -p 8080)
                command_parts.append(flag)
                command_parts.append(str(value))

        # Quote all parts safely for shell
        final_command = " ".join(shlex.quote(part) for part in command_parts)
        return final_command

    # ----------------------------------------------------------------------
    @staticmethod
    def build_from_manifest(manifest_data: dict, user_choices: dict) -> str:
        """
        Convenience function — build directly from manifest dictionary.
        """
        base_command = manifest_data.get("command", "")
        builder = CommandBuilder(base_command, user_choices)
        return builder.build()
