"""
ndiff_adapter.py
================

Interactive adapter for Ndiff. Loads yaml/Masscan/ndiff.yaml via ManifestLoader,
prompts user for options, validates inputs using validators.*, builds command tokens,
displays the final command and can execute it (streams output).

"""

import os
import shlex
from typing import List

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import file_validators


class NdiffAdapter:
    """Adapter class to handle Ndiff command construction (new manifest schema)."""

    def __init__(self, base_yaml_dir: str = "yaml"):
        self.logger = get_logger(__name__)
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Nmap"
        self.command_name = "ndiff"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)

    def _ask_enum(self, title: str, choices: list) -> List[str]:
        if not choices:
            return []
        print(f"\n{title}:")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c.get("id", str(c)))
            print(f"  {i}. {label}")
        while True:
            sel = input("Select number (0 to skip): ").strip()
            if sel in ("", "0"):
                return []
            if sel.isdigit() and 1 <= int(sel) <= len(choices):
                ch = choices[int(sel) - 1]
                tokens = []
                if ch.get("flag"):
                    tokens.append(ch["flag"])
                elif ch.get("value"):
                    tokens.append(ch["value"])
                return tokens
            print("[!] Enter a valid number.")

    def _prompt_file(self, prompt: str) -> str:
        while True:
            p = input(f"{prompt}: ").strip()
            try:
                file_validators.validate_file_exists(p)
                return p
            except Exception as e:
                print(f"[!] {e}")

    def build_command(self) -> dict:
        """Interactively build the ndiff command from manifest services."""
        services = self.manifest.get("services", [])
        if not services:
            raise RuntimeError("ndiff manifest missing 'services'")

        svc = services[0]  # only one: compare_xml
        cmd_parts: List[str] = ["ndiff"]

        placeholders = svc.get("placeholders", {})

        # output_format (enum of --text/--xml)
        fmt_tokens = self._ask_enum("Output format", placeholders.get("output_format", {}).get("choices", []))
        cmd_parts.extend(fmt_tokens)

        # verbosity (-v or empty)
        verb_tokens = self._ask_enum("Verbosity", placeholders.get("verbosity", {}).get("choices", []))
        cmd_parts.extend(verb_tokens)

        # two files
        f1 = self._prompt_file(placeholders.get("first_file", {}).get("prompt", "First XML file"))
        f2 = self._prompt_file(placeholders.get("second_file", {}).get("prompt", "Second XML file"))
        cmd_parts.extend([f1, f2])

        cmd_parts = [t for t in cmd_parts if t]
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        self.logger.info(f"Final ndiff command: {cmd_quoted}")
        return {"cmd_list": cmd_parts, "cmd_quoted": cmd_quoted, "manifest": self.manifest}


if __name__ == "__main__":
    adapter = NdiffAdapter()
    adapter.build_command()
