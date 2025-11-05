"""
Nping Adapter Module
--------------------
Handles construction and validation of nping commands based on nping.yaml manifest.
"""

import shlex
import subprocess
from typing import List

from manifest_loader import ManifestLoader
from core.logger import get_logger

class NpingAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.logger = get_logger(__name__)
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Nmap"
        self.command_name = "nping"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)

    def build_command(self) -> dict:
        """Construct nping command interactively using new manifest schema."""
        services = self.manifest.get("services", [])
        if not services:
            raise RuntimeError("nping manifest missing 'services'")
        svc = services[0]  # 'probe'
        placeholders = svc.get("placeholders", {})

        cmd_parts: List[str] = ["nping"]

        # mode enum
        mode_choices = placeholders.get("mode", {}).get("choices", [])
        if mode_choices:
            print("Select probe mode:")
            for i, c in enumerate(mode_choices, 1):
                print(f"  {i}. {c.get('label', c.get('id'))}")
            while True:
                s = input("Number (required): ").strip()
                if s.isdigit() and 1 <= int(s) <= len(mode_choices):
                    ch = mode_choices[int(s) - 1]
                    if ch.get("flag"):
                        cmd_parts.append(ch["flag"])
                    break
                print("[!] Enter a valid number.")

        # optional enums that might carry flags with args
        def ask_enum_arg(title: str, spec: dict):
            choices = spec.get("choices", [])
            if not choices:
                return
            print(f"\n{title}:")
            for i, c in enumerate(choices, 1):
                label = c.get("label", c.get("id"))
                print(f"  {i}. {label}")
            sel = input("Select number (0 to skip): ").strip()
            if sel and sel != "0" and sel.isdigit():
                ch = choices[int(sel) - 1]
                flag = ch.get("flag", "")
                argname = ch.get("arg")
                if argname:
                    val = input(f"Value for {argname}: ").strip()
                    if flag:
                        cmd_parts.extend([flag, val])
                    else:
                        cmd_parts.append(val)
                else:
                    if flag:
                        cmd_parts.append(flag)

        ask_enum_arg("Port option", placeholders.get("port_opt", {}))
        ask_enum_arg("Count option", placeholders.get("count_opt", {}))
        ask_enum_arg("Delay option", placeholders.get("delay_opt", {}))
        ask_enum_arg("TTL option", placeholders.get("ttl_opt", {}))
        ask_enum_arg("Verbosity", placeholders.get("verbosity", {}))

        # target
        target_prompt = placeholders.get("target", {}).get("prompt", "Target host or IP")
        target = input(f"{target_prompt}: ").strip()
        if target:
            cmd_parts.append(target)

        cmd_parts = [p for p in cmd_parts if p]
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)
        self.logger.info(f"Constructed nping command: {cmd_quoted}")
        return {"cmd_list": cmd_parts, "cmd_quoted": cmd_quoted, "manifest": self.manifest}

    def run_command(self, command):
        """
        Executes nping command using subprocess.
        """
        try:
            self.logger.info("Executing nping command...")
            process = subprocess.Popen(
                command if isinstance(command, list) else command,
                shell=not isinstance(command, list),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                self.logger.info("Nping command executed successfully.")
                print(stdout.decode())
            else:
                self.logger.error("Error while executing nping:")
                print(stderr.decode())

        except KeyboardInterrupt:
            self.logger.warning("Execution interrupted by user.")
        except Exception as e:
            self.logger.error(f"Execution failed: {e}")
