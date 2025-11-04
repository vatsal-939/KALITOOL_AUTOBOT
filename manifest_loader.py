"""
manifest_loader.py
==================
This module handles the loading and validation of YAML manifest files.
Each YAML file describes the structure of a security tool (commands, flags, examples, etc.)
and is later interpreted by the Engine to build executable command lines.

Responsibilities:
    - Locate YAML files for each tool
    - Load and parse YAML content safely
    - Validate YAML structure and keys
    - Return manifest dictionary for further processing
"""

import os
import yaml


class ManifestLoader:
    """
    Loads and validates YAML manifests for tools like Nmap, Sqlmap, etc.
    """

    def __init__(self, base_yaml_dir: str):
        """
        Initialize the loader with a base YAML directory.
        :param base_yaml_dir: Directory containing YAML files (e.g., './yaml')
        """
        self.base_yaml_dir = base_yaml_dir

    # ----------------------------------------------------------------------
    def _validate_manifest_structure(self, manifest_data: dict, yaml_file: str):
        """
        Validate the YAML structure to ensure required keys exist.
        Supports both old format (tool/command/flags) and new format (tool_id/command_id/services).
        """
        # Check for old format
        if "tool" in manifest_data and "command" in manifest_data:
            # Old format: require flags
            if "flags" not in manifest_data:
                raise ValueError(
                    f"[ERROR] YAML manifest '{yaml_file}' missing required key: 'flags'"
                )
            if not isinstance(manifest_data["flags"], (list, dict)):
                raise ValueError(
                    f"[ERROR] 'flags' in {yaml_file} must be a list or dict, got {type(manifest_data['flags'])}"
                )
        # Check for new format
        elif "tool_id" in manifest_data and "command_id" in manifest_data:
            # New format: require services
            if "services" not in manifest_data:
                raise ValueError(
                    f"[ERROR] YAML manifest '{yaml_file}' missing required key: 'services'"
                )
        else:
            # Neither format found
            raise ValueError(
                f"[ERROR] YAML manifest '{yaml_file}' must have either (tool/command) or (tool_id/command_id)"
            )

        return True

    # ----------------------------------------------------------------------
    def load_manifest(self, tool_name: str, command_name: str) -> dict:
        """
        Load a specific YAML manifest for a given tool and command.
        Example:
            tool_name='Nmap', command_name='ncat'
        will load './yaml/Nmap/ncat.yaml'
        """
        yaml_path = os.path.join(self.base_yaml_dir, tool_name, f"{command_name}.yaml")

        if not os.path.exists(yaml_path):
            raise FileNotFoundError(f"[ERROR] Manifest file not found: {yaml_path}")

        with open(yaml_path, "r") as file:
            try:
                manifest_data = yaml.safe_load(file)
            except yaml.YAMLError as e:
                raise ValueError(f"[ERROR] Invalid YAML format in {yaml_path}: {e}")

        # Validate structure
        self._validate_manifest_structure(manifest_data, yaml_path)

        return manifest_data

    # ----------------------------------------------------------------------
    def list_available_manifests(self) -> dict:
        """
        List all available manifests grouped by tool name.
        Returns:
            {
                "Nmap": ["ncat", "nmap", "nping", "zenmap"],
                "Sqlmap": ["sqlmap", "sqlmapapi"]
            }
        """
        tools_dict = {}
        if not os.path.exists(self.base_yaml_dir):
            raise FileNotFoundError(f"[ERROR] YAML directory not found: {self.base_yaml_dir}")

        for tool_folder in os.listdir(self.base_yaml_dir):
            tool_path = os.path.join(self.base_yaml_dir, tool_folder)
            if os.path.isdir(tool_path):
                commands = [
                    f.replace(".yaml", "")
                    for f in os.listdir(tool_path)
                    if f.endswith(".yaml")
                ]
                tools_dict[tool_folder] = commands

        return tools_dict
