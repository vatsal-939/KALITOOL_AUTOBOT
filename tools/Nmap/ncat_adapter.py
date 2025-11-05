"""
tools/Nmap/ncat_adapter.py — UPDATED

Improvements:
 - Supports repeating '-v' according to a numeric verbosity count (e.g., -v -v -v)
 - Validates CSV lists (hosts/hops) and numeric args
 - Re-prompts on invalid input
 - Requires explicit confirmation for high-risk flags
 - Keeps returning both cmd_list and cmd_quoted

Depends on:
 - manifest_loader.ManifestLoader (load_manifest(tool, command))
 - validators.network_validators
 - validators.file_validators
 - validators.input_validators
 - core.logger.get_logger
"""

import os
import shlex
from typing import Dict, Any, List, Tuple

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import network_validators, file_validators, input_validators

logger = get_logger(__name__)


class NcatAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Nmap"
        self.command_name = "ncat"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        self.services = self.manifest.get("services", [])
        if not self.services:
            raise RuntimeError("ncat manifest has no 'services' section")

    # -------------------------
    # Helper validators / prompts
    # -------------------------
    def _prompt_int(self, prompt: str, min_val: int = None, max_val: int = None, allow_empty=False) -> int:
        while True:
            s = input(f"{prompt}: ").strip()
            if s == "" and allow_empty:
                return None
            if not input_validators.validate_integer(s):
                print("[!] Please enter an integer value.")
                continue
            v = int(s)
            if min_val is not None and v < min_val:
                print(f"[!] Value must be >= {min_val}.")
                continue
            if max_val is not None and v > max_val:
                print(f"[!] Value must be <= {max_val}.")
                continue
            return v

    def _prompt_time(self, prompt: str, allow_empty=False) -> str:
        # Accepts values like '500ms', '30s', '2m', '1h' or bare numbers (seconds)
        while True:
            s = input(f"{prompt} (e.g. 500ms, 30s, 2m) : ").strip()
            if s == "" and allow_empty:
                return ""
            # simple validation
            if s.endswith(("ms", "s", "m", "h")):
                num = s[:-2] if s.endswith("ms") else s[:-1]
                if num.replace(".", "", 1).isdigit():
                    return s
            elif s.replace(".", "", 1).isdigit():
                return s
            print("[!] Invalid time format. Use digits optionally suffixed with ms/s/m/h.")

    def _prompt_path_existing(self, prompt: str, allow_empty=False) -> str:
        while True:
            p = input(f"{prompt}: ").strip()
            if p == "" and allow_empty:
                return ""
            try:
                file_validators.validate_file_exists(p)
                return p
            except Exception as e:
                print(f"[!] {e}. Try again or leave blank to skip.")

    def _prompt_host_or_ip(self, prompt: str, allow_empty=False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                network_validators.validate_host_or_path(v)
                return v
            except ValueError as e:
                print(f"[!] {e}")

    def _prompt_hostport(self, prompt: str, allow_empty=False) -> str:
        while True:
            v = input(f"{prompt} (host:port or port): ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                if ":" in v:
                    network_validators.validate_host_and_port(v)
                else:
                    network_validators.validate_port(v)
                return v
            except ValueError as e:
                print(f"[!] {e}")

    def _prompt_csv_hosts(self, prompt: str, allow_empty=False) -> str:
        """
        Prompt for comma-separated hosts/hops. Validate each item (if looks like IP/host).
        Returns raw CSV string (trimmed).
        """
        while True:
            s = input(f"{prompt} (comma separated): ").strip()
            if s == "" and allow_empty:
                return ""
            parts = [p.strip() for p in s.split(",") if p.strip()]
            if len(parts) == 0:
                print("[!] Enter one or more comma-separated values or leave blank to skip.")
                continue
            ok = True
            for p in parts:
                # allow numeric hops (for -G pointer) else validate host/ip loosely
                if all(ch.isdigit() for ch in p):
                    continue
                try:
                    network_validators.validate_host_or_path(p)
                except ValueError as e:
                    print(f"[!] Invalid entry '{p}': {e}")
                    ok = False
                    break
            if ok:
                return ",".join(parts)

    def _ask_yes_no(self, q: str) -> bool:
        while True:
            r = input(f"{q} (y/n): ").strip().lower()
            if r in ("y", "yes"):
                return True
            if r in ("n", "no"):
                return False
            print("[!] please answer y or n")

    # -------------------------
    # Choice prompts (enum / multi_enum)
    # -------------------------
    def _ask_enum(self, placeholder_name: str, spec: dict) -> Tuple[List[str], List[dict]]:
        """
        Return a list of tokens (each token is a single flag or flag+arg) and list of chosen choice dicts.
        """
        choices = spec.get("choices", [])
        if not choices:
            return [], []
        print(f"\nChoose {placeholder_name}:")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c.get("id", str(c)))
            flag = c.get("flag", "")
            arg = c.get("arg")
            print(f"  {i}. {label}  (flag='{flag}'{' arg=' + arg if arg else ''})")
        while True:
            sel = input("Select number (0 to skip): ").strip()
            if sel == "0" or sel == "":
                return [], []
            if not sel.isdigit():
                print("[!] enter a number")
                continue
            idx = int(sel) - 1
            if 0 <= idx < len(choices):
                choice = choices[idx]
                tokens = []
                flag = choice.get("flag", "")
                # handle verbosity separately by returning metadata
                if choice.get("id") == "verbose" and choice.get("arg") == "count":
                    count = self._prompt_int("Verbosity count (number of -v repeats)", min_val=1, max_val=10)
                    tokens = ["-v"] * count
                elif "arg" in choice:
                    arg_name = choice["arg"]
                    if arg_name in ("file",):
                        val = self._prompt_path_existing(f"Value for {arg_name}")
                        tokens = [flag, val] if flag else [val]
                    elif arg_name in ("port",):
                        val = self._prompt_int(f"Value for {arg_name}", min_val=1, max_val=65535)
                        tokens = [flag, str(val)] if flag else [str(val)]
                    elif arg_name in ("n",):
                        val = self._prompt_int(f"Value for {arg_name}", min_val=1)
                        tokens = [flag, str(val)]
                    elif arg_name in ("time",):
                        val = self._prompt_time(f"Value for {arg_name}", allow_empty=False)
                        tokens = [flag, val]
                    elif arg_name in ("hops", "hosts"):
                        val = self._prompt_csv_hosts(f"Value for {arg_name}")
                        tokens = [flag, val]
                    elif arg_name in ("auth", "protos", "ciphers", "name", "addr", "filelist"):
                        # general string or hostport handling
                        val = input(f"Enter value for {arg_name}: ").strip()
                        tokens = [flag, val] if flag else [val]
                    else:
                        val = input(f"Enter value for {arg_name}: ").strip()
                        tokens = [flag, val] if flag else [val]
                else:
                    # flag only
                    if flag:
                        tokens = [flag]
                    else:
                        # some choices might be value-only (proxy type value)
                        val = choice.get("value")
                        tokens = [val] if val else []
                return tokens, [choice]
            else:
                print("[!] invalid selection")

    def _ask_multi_enum(self, placeholder_name: str, spec: dict) -> Tuple[List[str], List[dict]]:
        """
        Multi-select returns combined tokens and list of chosen dicts.
        """
        choices = spec.get("choices", [])
        if not choices:
            return [], []
        print(f"\nMulti-select options for {placeholder_name} (comma-separated numbers, 0 to skip):")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c.get("id", str(c)))
            print(f"  {i}. {label}  (flag='{c.get('flag','')}')")
        while True:
            sel = input("Select numbers (e.g., 1,3) or 0 to skip: ").strip()
            if sel == "0" or sel == "":
                return [], []
            parts = [s.strip() for s in sel.split(",") if s.strip()]
            ok = True
            tokens = []
            chosen = []
            for p in parts:
                if not p.isdigit() or int(p) < 1 or int(p) > len(choices):
                    ok = False
                    break
            if not ok:
                print("[!] invalid selection; try again.")
                continue
            for p in parts:
                choice = choices[int(p) - 1]
                # re-use enum handling per choice if arg present
                if "arg" in choice:
                    toks, ch = self._ask_enum(f"{placeholder_name}:{choice.get('label')}", {"choices": [choice]})
                    tokens.extend(toks)
                    chosen.extend(ch)
                else:
                    flag = choice.get("flag", "")
                    if flag:
                        tokens.append(flag)
                    chosen.append(choice)
            return tokens, chosen

    # -------------------------
    # Core builder
    # -------------------------
    def _choose_service(self) -> Dict[str, Any]:
        print("\nAvailable ncat services:")
        for i, s in enumerate(self.services, 1):
            label = s.get("label", s.get("id", f"service_{i}"))
            desc = s.get("description", "")
            print(f"  {i}. {label} - {desc}")
        while True:
            choice = input("Select service number: ").strip()
            if not choice.isdigit():
                print("Please enter a number.")
                continue
            idx = int(choice) - 1
            if 0 <= idx < len(self.services):
                return self.services[idx]
            print("Invalid selection, try again.")

    def build_command(self) -> Dict[str, Any]:
        service = self._choose_service()
        placeholders = service.get("placeholders", {})
        placeholder_values_tokens: Dict[str, List[str]] = {}
        chosen_choices = []  # collect chosen choice metadata for risk checks

        print("\nPlease answer the following for chosen service:\n")
        for name, spec in placeholders.items():
            ptype = spec.get("type", "string")
            if ptype == "enum":
                toks, chosen = self._ask_enum(name, spec)
                if toks:
                    placeholder_values_tokens[name] = toks
                    chosen_choices.extend(chosen)
            elif ptype == "multi_enum":
                toks, chosen = self._ask_multi_enum(name, spec)
                if toks:
                    placeholder_values_tokens[name] = toks
                    chosen_choices.extend(chosen)
            elif ptype in ("hostport", "hostport_or_port", "hostport_or_port"):
                val = self._prompt_hostport(spec.get("prompt", name), allow_empty=True)
                if val:
                    placeholder_values_tokens[name] = [val]
            elif ptype in ("filepath", "file", "filepath_optional"):
                val = self._prompt_path_existing(spec.get("prompt", name), allow_empty=True)
                if val:
                    placeholder_values_tokens[name] = [val]
            elif ptype in ("hostname_or_ip", "hostname_or_ip_and_port", "host", "target_multi"):
                val = self._prompt_host_or_ip(spec.get("prompt", name), allow_empty=True)
                if val:
                    placeholder_values_tokens[name] = [val]
            elif ptype in ("port", "port_optional"):
                if ptype == "port":
                    v = self._prompt_int(spec.get("prompt", name), min_val=1, max_val=65535)
                    placeholder_values_tokens[name] = [str(v)]
                else:
                    v = self._prompt_int(spec.get("prompt", name), min_val=1, max_val=65535, allow_empty=True)
                    if v is not None:
                        placeholder_values_tokens[name] = [str(v)]
            elif ptype in ("string_optional", "string"):
                val = input(f"{spec.get('prompt', name)}: ").strip()
                if val != "":
                    placeholder_values_tokens[name] = [val]
            else:
                # unknown type: fallback to generic prompt
                val = input(f"{spec.get('prompt', name)}: ").strip()
                if val != "":
                    placeholder_values_tokens[name] = [val]

        # If any chosen choice has risk: high, require explicit confirmation
        high_risk = [c for c in chosen_choices if c.get("risk") == "high" or c.get("risk") == "High"]
        if high_risk:
            print("\nWARNING: You selected HIGH-RISK options:")
            for c in high_risk:
                print("  -", c.get("label", c.get("id")))
            ok = self._ask_yes_no("Do you have authorization and want to proceed with HIGH-RISK options?")
            if not ok:
                raise RuntimeError("User did not confirm high-risk execution.")

        # Build command from command_template
        cmd_template: List[str] = service.get("command_template", [])
        cmd_parts: List[str] = []
        for tok in cmd_template:
            if isinstance(tok, str) and tok.startswith("{") and tok.endswith("}"):
                key = tok[1:-1]
                vals = placeholder_values_tokens.get(key, [])
                # append tokens directly
                for v in vals:
                    # if a token contains spaces (rare), split carefully
                    cmd_parts.extend(v.split())
            else:
                if tok != "":
                    cmd_parts.append(tok)

        # Ensure command starts with 'ncat'
        if not cmd_parts or cmd_parts[0] != "ncat":
            cmd_parts.insert(0, "ncat")

        # Post-process: collapse duplicate spaces, etc.
        # Quote command for display
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        return {
            "cmd_list": cmd_parts,
            "cmd_quoted": cmd_quoted,
            "manifest": self.manifest,
            "service": service,
            "placeholders_tokens": placeholder_values_tokens,
            "chosen_choices": chosen_choices,
        }


if __name__ == "__main__":
    # quick smoke test if run directly
    try:
        adapter = NcatAdapter(base_yaml_dir="yaml")
        res = adapter.build_command()
        print("\nGenerated list:", res["cmd_list"])
        print("Quoted:", res["cmd_quoted"])
    except Exception as exc:
        print("Adapter error:", exc)
