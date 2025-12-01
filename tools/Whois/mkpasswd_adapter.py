"""
tools/Whois/mkpasswd_adapter.py

Interactive adapter for mkpasswd (from the whois package).
Loads yaml/Whois/mkpasswd.yaml, prompts the user for hashing options,
validates inputs using validators.*, builds the mkpasswd command, shows it,
and optionally executes it.

Place this file at: tools/Whois/mkpasswd_adapter.py
"""

import shlex
import subprocess
from typing import Dict, Any, List, Optional

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import file_validators, input_validators

logger = get_logger(__name__)


class MkpasswdAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Whois"
        self.command_name = "mkpasswd"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        if not self.manifest:
            raise RuntimeError("mkpasswd manifest not found")
        self.services = self.manifest.get("services", [])

    # ------------------------
    # Input helpers
    # ------------------------
    def _yes_no(self, question: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            r = input(f"{question} ({hint}): ").strip().lower()
            if r == "" and default:
                return True
            if r in ("y", "yes"):
                return True
            if r in ("n", "no"):
                return False
            print("[!] Enter y or n")

    def _prompt_string(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            if v != "" or allow_empty:
                return v

    def _prompt_numeric(self, prompt: str, allow_empty: bool = False) -> Optional[int]:
        while True:
            val = input(f"{prompt}: ").strip()
            if val == "" and allow_empty:
                return None
            if input_validators.validate_integer(val):
                return int(val)
            print("[!] Enter a valid integer.")

    def _prompt_enum(self, choices: List[dict], prompt="Select option") -> Optional[dict]:
        print(prompt)
        for idx, c in enumerate(choices, 1):
            print(f"  {idx}. {c.get('label', c['id'])} ({c['arg']})")
        print("  0. Skip")

        while True:
            sel = input("Choose: ").strip()
            if sel == "0" or sel == "":
                return None
            if sel.isdigit() and 1 <= int(sel) <= len(choices):
                return choices[int(sel) - 1]
            print("[!] Invalid choice.")

    # ------------------------
    # Service selection helper
    # ------------------------
    def _choose_service(self) -> Optional[Dict[str, Any]]:
        """Allow user to select which service to configure."""
        print("\nAvailable mkpasswd configuration groups (services):")
        for i, s in enumerate(self.services, 1):
            label = s.get("label", s.get("id", f"service_{i}"))
            desc = s.get("description", "")
            print(f"  {i}. {label} — {desc}")
        while True:
            sel = input("Select service number to configure (0 to finish selection): ").strip()
            if sel == "0":
                return None
            if not sel.isdigit():
                print("[!] Enter a number.")
                continue
            idx = int(sel) - 1
            if 0 <= idx < len(self.services):
                return self.services[idx]
            print("[!] Invalid selection.")

    def _process_service(self, service: Dict[str, Any], cmd: List[str], chosen_meta: List[dict]):
        """Process a single selected service and add flags to cmd."""
        svc_id = service.get("id")
        placeholders = service.get("placeholders", {}) or {}

        if svc_id == "hashing_options":
            # METHOD enum
            if "method" in placeholders:
                enum_spec = placeholders["method"]
                method = self._prompt_enum(
                    enum_spec.get("choices", []),
                    prompt="Choose hashing method (--method)"
                )
                if method:
                    cmd.extend(["--method", method["arg"]])
                    chosen_meta.append(method)

            # -5 shortcut
            if "method_md5_shortcut" in placeholders:
                if self._yes_no("Enable MD5 shortcut (-5)?", default=False):
                    cmd.append("-5")

            # SALT
            if "salt" in placeholders:
                v = self._prompt_string("Custom salt (--salt) (blank = random)", allow_empty=True)
                if v:
                    cmd.extend(["--salt", v])

            # ROUNDS
            if "rounds" in placeholders:
                v = self._prompt_numeric("Number of rounds (--rounds) (blank to skip)", allow_empty=True)
                if v:
                    cmd.extend(["--rounds", str(v)])

            # PASSWORD-FD
            if "password_fd" in placeholders:
                v = self._prompt_numeric("Read password from FD (--password-fd) (blank to skip)", allow_empty=True)
                if v is not None:
                    cmd.extend(["--password-fd", str(v)])

            # STDIN
            if "stdin_input" in placeholders:
                if self._yes_no("Read password from STDIN (--stdin)?", default=False):
                    cmd.append("--stdin")

            # HELP
            if "help" in placeholders:
                if self._yes_no("Add --help?", default=False):
                    cmd.append("--help")

            # VERSION
            if "version" in placeholders:
                if self._yes_no("Add --version?", default=False):
                    cmd.append("--version")

        elif svc_id == "password_input":
            # Password and salt arguments
            if "password" in placeholders:
                pw = self._prompt_string(
                    "Enter PASSWORD argument (blank = interactive password)",
                    allow_empty=True
                )
                if pw:
                    cmd.append(pw)

            if "salt" in placeholders:
                slt = self._prompt_string(
                    "Enter SALT argument (blank = auto/random or from --salt)",
                    allow_empty=True
                )
                if slt:
                    cmd.append(slt)

    # ------------------------
    # Main builder
    # ------------------------
    def build_command(self) -> Dict[str, Any]:
        cmd = ["mkpasswd"]
        chosen_meta = []

        if not self.services:
            raise RuntimeError("mkpasswd manifest contains no services")

        print("\nConfigure mkpasswd command. You will be able to add multiple groups (Hashing Options, Password Input).")

        # Allow user to select which services to configure
        while True:
            service = self._choose_service()
            if service is None:
                break

            print(f"\nConfiguring: {service.get('label')}")

            # Process the selected service
            self._process_service(service, cmd, chosen_meta)

            # Ask user whether to continue adding other groups
            cont = self._yes_no("Do you want to configure another mkpasswd group?", default=True)
            if not cont:
                break

        # ------------------------
        # Final command display
        # ------------------------
        final_cmd = " ".join(shlex.quote(c) for c in cmd)

        print("\nGenerated mkpasswd command:")
        print(final_cmd)

        if self._yes_no("Execute this command?", default=False):
            rc = self.execute_command(cmd)
            print(f"[+] Process exited with code {rc}")
        else:
            print("[*] Execution skipped.")

        return {
            "cmd_list": cmd,
            "cmd_quoted": final_cmd,
            "chosen_meta": chosen_meta
        }

    # ------------------------
    # Executor
    # ------------------------
    def execute_command(self, cmd_list: List[str]) -> int:
        logger.info("Running: %s", " ".join(cmd_list))
        try:
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate()
            if out:
                print(out)
            if err:
                print(err)
            return proc.returncode or 0
        except FileNotFoundError:
            print("[!] mkpasswd not found. Install 'whois' package.")
            return -1
        except Exception as e:
            print(f"[!] execution failed: {e}")
            return -2


if __name__ == "__main__":
    adapter = MkpasswdAdapter(base_yaml_dir="yaml")
    result = adapter.build_command()
