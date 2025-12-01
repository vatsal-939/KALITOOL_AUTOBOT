"""
tools/Whois/whois_adapter.py

Interactive adapter for the `whois` CLI. Loads yaml/Whois/whois.yaml via
ManifestLoader, prompts the user for options grouped into Standard and
RIPE-style sections, validates inputs with validators.*, builds the whois
command, displays it, and optionally executes it while streaming output.

Save path: tools/Whois/whois_adapter.py
"""

import shlex
import subprocess
from typing import Dict, Any, List, Optional

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import input_validators, file_validators, network_validators

logger = get_logger(__name__)


class WhoisAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Whois"
        self.command_name = "whois"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        if not self.manifest:
            raise RuntimeError("whois manifest not found")
        self.services = self.manifest.get("services", [])

    # -------------------------
    # Basic prompt helpers
    # -------------------------
    def _ask_yes_no(self, prompt: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            r = input(f"{prompt} ({hint}): ").strip().lower()
            if r == "" and default:
                return True
            if r in ("y", "yes"):
                return True
            if r in ("n", "no"):
                return False
            print("[!] please answer y or n")

    def _prompt_string(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            if v != "" or allow_empty:
                return v

    def _prompt_numeric(self, prompt: str, allow_empty: bool = False) -> Optional[int]:
        while True:
            s = input(f"{prompt}: ").strip()
            if s == "" and allow_empty:
                return None
            if input_validators.validate_integer(s):
                return int(s)
            print("[!] enter a valid integer")

    # -------------------------
    # Group-specific handlers
    # -------------------------
    def _handle_standard(self, placeholders: Dict[str, Any], cmd_parts: List[str], chosen: List[dict]):
        # host (--host / -h)
        if "host" in placeholders:
            host = self._prompt_string("WHOIS server hostname (-h/--host) (press Enter to skip)", allow_empty=True)
            if host:
                cmd_parts.extend(["-h", host])
                chosen.append({"host": host})

        # port (--port / -p)
        if "port" in placeholders:
            port = self._prompt_numeric("WHOIS server port (-p/--port) (press Enter to skip)", allow_empty=True)
            if port is not None:
                cmd_parts.extend(["-p", str(port)])
                chosen.append({"port": port})

        # query iana (-I)
        if "query_iana" in placeholders and self._ask_yes_no("Query whois.iana.org and follow referral (-I)?", default=False):
            cmd_parts.append("-I")
            chosen.append({"query_iana": True})

        # hide disclaimer (-H)
        if "hide_disclaimer" in placeholders and self._ask_yes_no("Hide legal disclaimers (-H)?", default=False):
            cmd_parts.append("-H")
            chosen.append({"hide_disclaimer": True})

        # verbose
        if "verbose" in placeholders and self._ask_yes_no("Verbose mode (--verbose)?", default=False):
            cmd_parts.append("--verbose")
            chosen.append({"verbose": True})

        # no-recursion
        if "no_recursion" in placeholders and self._ask_yes_no("Disable recursion (--no-recursion)?", default=False):
            cmd_parts.append("--no-recursion")
            chosen.append({"no_recursion": True})

        # help
        if "help" in placeholders and self._ask_yes_no("Add --help?", default=False):
            cmd_parts.append("--help")
            chosen.append({"help": True})

        # version
        if "version" in placeholders and self._ask_yes_no("Add --version?", default=False):
            cmd_parts.append("--version")
            chosen.append({"version": True})

    def _handle_ripe(self, placeholders: Dict[str, Any], cmd_parts: List[str], chosen: List[dict]):
        # simple flags first
        simple_flags = [
            ("less_specific_1", "-l"),
            ("less_specific_all", "-L"),
            ("more_specific_1", "-m"),
            ("more_specific_all", "-M"),
            ("mnt_irt", "-c"),
            ("exact_match", "-x"),
            ("brief", "-b"),
            ("no_filtering", "-B"),
            ("no_grouping", "-G"),
            ("include_dns_reverse", "-d"),
            ("primary_keys_only", "-K"),
            ("no_recursive_contacts", "-r"),
            ("show_local_copy", "-R"),
            ("search_all_mirrors", "-a"),
        ]
        for key, flag in simple_flags:
            if key in placeholders and self._ask_yes_no(f"Enable {flag}? ({placeholders[key].get('prompt','')})", default=False):
                cmd_parts.append(flag)
                chosen.append({key: True})

        # inverse lookup (-i)
        if "inverse_lookup" in placeholders:
            v = self._prompt_string("Inverse lookup attributes (-i ATTR[,ATTR]...) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-i", v])
                chosen.append({"inverse_lookup": v})

        # type filter (-T)
        if "type_filter" in placeholders:
            v = self._prompt_string("Type filter (-T TYPE[,TYPE]...) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-T", v])
                chosen.append({"type_filter": v})

        # source filter (-s)
        if "source_filter" in placeholders:
            v = self._prompt_string("Source list (-s SOURCE[,SOURCE]...) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-s", v])
                chosen.append({"source_filter": v})

        # serial range (-g)
        if "serial_range" in placeholders:
            v = self._prompt_string("Serial range (-g SOURCE:FIRST-LAST) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-g", v])
                chosen.append({"serial_range": v})

        # request template (-t)
        if "request_template" in placeholders:
            v = self._prompt_string("Request template (-t TYPE) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-t", v])
                chosen.append({"request_template": v})

        # request template verbose (-v)
        if "request_template_verbose" in placeholders:
            v = self._prompt_string("Verbose request template (-v TYPE) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-v", v])
                chosen.append({"request_template_verbose": v})

        # query server info (-q)
        if "query_server_info" in placeholders:
            v = self._prompt_string("Query server info (-q [version|sources|types]) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-q", v])
                chosen.append({"query_server_info": v})

    # -------------------------
    # Service selection helper
    # -------------------------
    def _choose_service(self) -> Optional[Dict[str, Any]]:
        """Allow user to select which service to configure."""
        print("\nAvailable whois configuration groups (services):")
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

    def _process_service(self, service: Dict[str, Any], cmd_parts: List[str], chosen_meta: List[dict]):
        """Process a single selected service and add flags to cmd_parts."""
        svc_id = service.get("id")
        placeholders = service.get("placeholders", {}) or {}
        
        if svc_id == "standard_whois":
            self._handle_standard(placeholders, cmd_parts, chosen_meta)
        elif svc_id == "ripe_whois":
            self._handle_ripe(placeholders, cmd_parts, chosen_meta)
        elif svc_id == "query_object":
            # Handle query object (required argument)
            obj = self._prompt_string("Enter the WHOIS object (domain, IP, ASN, or handle): ", allow_empty=False)
            cmd_parts.append(obj)
            chosen_meta.append({"object": obj})
        else:
            # Generic handling for unknown service: ask for flags or values
            for name, spec in placeholders.items():
                if spec.get("type") == "flag":
                    if self._ask_yes_no(f"Enable {name}?", default=False):
                        cmd_parts.append(spec.get("flag", f"--{name}"))
                        chosen_meta.append({name: True})
                else:
                    val = self._prompt_string(spec.get("prompt", name), allow_empty=True)
                    if val:
                        fl = spec.get("flag")
                        if fl:
                            cmd_parts.extend([fl, val])
                        else:
                            cmd_parts.append(val)
                        chosen_meta.append({name: val})

    # -------------------------
    # Build + execute
    # -------------------------
    def build_command(self) -> Dict[str, Any]:
        cmd_parts: List[str] = ["whois"]
        chosen_meta: List[dict] = []

        if not self.services:
            raise RuntimeError("whois manifest contains no services")

        print("\nConfigure whois command. You will be able to add multiple groups (Standard WHOIS, RIPE-style, Query Object).")

        # Allow user to select which services to configure
        while True:
            service = self._choose_service()
            if service is None:
                break

            print(f"\nConfiguring: {service.get('label')}")

            # Process the selected service
            self._process_service(service, cmd_parts, chosen_meta)

            # Ask user whether to continue adding other groups
            cont = self._ask_yes_no("Do you want to configure another whois group?", default=True)
            if not cont:
                break

        # Ensure query_object was provided (required)
        has_object = any("object" in m for m in chosen_meta)
        if not has_object:
            print("\n[!] Query object is required. Adding it now...")
            obj = self._prompt_string("Enter the WHOIS object (domain, IP, ASN, or handle): ", allow_empty=False)
            cmd_parts.append(obj)
            chosen_meta.append({"object": obj})

        # Clean and create quoted form
        cmd_parts = [p for p in cmd_parts if p and str(p).strip() != ""]
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        print("\nGenerated whois command:")
        print(cmd_quoted)

        if self._ask_yes_no("Execute this whois command now?", default=False):
            rc = self.execute_command(cmd_parts)
            print(f"[+] Process exited with code: {rc}")
        else:
            print("Execution skipped by user.")

        return {
            "cmd_list": cmd_parts,
            "cmd_quoted": cmd_quoted,
            "chosen_meta": chosen_meta,
        }

    def execute_command(self, cmd_list: List[str]) -> int:
        logger.info("Executing: %s", " ".join(cmd_list))
        try:
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                # stream stdout
                while True:
                    out_line = proc.stdout.readline()
                    if out_line:
                        print(out_line.rstrip())
                    elif proc.poll() is not None:
                        break
                # remaining stderr
                stderr = proc.stderr.read()
                if stderr:
                    print(stderr.rstrip())
                return proc.returncode if proc.returncode is not None else 0
            except KeyboardInterrupt:
                proc.terminate()
                logger.warning("Execution interrupted by user.")
                return -1
        except FileNotFoundError:
            logger.error("whois binary not found in PATH.")
            print("Error: 'whois' not found. Is the whois package installed and available in PATH?")
            return -2
        except Exception as e:
            logger.error("Execution failed: %s", e)
            print(f"Execution failed: {e}")
            return -3


if __name__ == "__main__":
    adapter = WhoisAdapter(base_yaml_dir="yaml")
    res = adapter.build_command()
    print("\nCommand List:", res["cmd_list"])
    print("Quoted:", res["cmd_quoted"])
