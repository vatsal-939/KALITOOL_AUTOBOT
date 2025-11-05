"""
tools/Nmap/nmap_adapter.py

Interactive adapter to build Nmap commands from yaml/Nmap/nmap.yaml.

Behavior:
 - Loads manifest via ManifestLoader(base_yaml_dir)
 - Shows available services (logical groups) and lets user choose which ones to configure
 - Prompts for placeholders, validates with validators.*, and assembles cmd_list
 - Demands extra confirmation when high-risk flags are selected
 - Returns dict with cmd_list, cmd_quoted, manifest, and chosen metadata
"""

import shlex
from typing import Dict, Any, List, Tuple

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import input_validators, file_validators, network_validators

logger = get_logger(__name__)


class NmapAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Nmap"
        self.command_name = "nmap"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        self.services = self.manifest.get("services", [])
        if not self.services:
            raise RuntimeError("nmap manifest has no 'services' section")

    # -------------------------
    # Basic prompts & validators
    # -------------------------
    def _ask_yes_no(self, prompt: str, default: bool = False) -> bool:
        default_str = "Y/n" if default else "y/N"
        while True:
            r = input(f"{prompt} ({default_str}): ").strip().lower()
            if r == "" and default:
                return True
            if r in ("y", "yes"):
                return True
            if r in ("n", "no"):
                return False
            print("[!] Please answer y or n.")

    def _prompt_string(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            if v != "" or allow_empty:
                return v

    def _prompt_filepath(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            p = input(f"{prompt}: ").strip()
            if p == "" and allow_empty:
                return ""
            try:
                file_validators.validate_file_exists(p)
                return p
            except Exception as e:
                print(f"[!] {e}")

    def _prompt_int(self, prompt: str, min_v: int = None, max_v: int = None, allow_empty: bool = False) -> int:
        while True:
            s = input(f"{prompt}: ").strip()
            if s == "" and allow_empty:
                return None
            if not input_validators.validate_integer(s):
                print("[!] Enter an integer.")
                continue
            v = int(s)
            if min_v is not None and v < min_v:
                print(f"[!] Minimum value: {min_v}")
                continue
            if max_v is not None and v > max_v:
                print(f"[!] Maximum value: {max_v}")
                continue
            return v

    def _prompt_time(self, prompt: str, allow_empty: bool = False) -> str:
        # Accept simple time formats: numbers optionally suffixed with ms/s/m/h
        while True:
            s = input(f"{prompt} (e.g. 500ms, 30s, 2m): ").strip()
            if s == "" and allow_empty:
                return ""
            if s.endswith(("ms", "s", "m", "h")) or s.replace(".", "", 1).isdigit():
                return s
            print("[!] Invalid time format.")

    def _prompt_portspec(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            s = input(f"{prompt} (e.g. 22,80,1-1024): ").strip()
            if s == "" and allow_empty:
                return ""
            if input_validators.validate_port_range(s):
                return s
            print("[!] Invalid port list/range.")

    def _prompt_hostspec(self, prompt: str, allow_empty: bool = False) -> str:
        # target_multi may be complex; accept string and rely on manifest-level validation
        while True:
            s = input(f"{prompt}: ").strip()
            if s == "" and allow_empty:
                return ""
            # try loose validation: accept host, ip, network or comma-separated list
            # We won't be overly strict here; engine can rely on nmap errors for complex specs
            return s

    def _prompt_csv(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            s = input(f"{prompt} (comma-separated): ").strip()
            if s == "" and allow_empty:
                return ""
            parts = [x.strip() for x in s.split(",") if x.strip()]
            if not parts:
                print("[!] Enter at least one item or leave blank.")
                continue
            return ",".join(parts)

    # -------------------------
    # Choice handlers (enum/multi_enum)
    # -------------------------
    def _ask_enum(self, placeholder_name: str, spec: dict) -> Tuple[List[str], List[dict]]:
        """
        Present single-choice enumerations. Returns token list and chosen metadata.
        """
        choices = spec.get("choices", [])
        if not choices:
            return [], []
        print(f"\nChoose {placeholder_name}:")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c.get("id", str(c)))
            flag = c.get("flag", "")
            arg = c.get("arg", "")
            print(f"  {i}. {label}  (flag='{flag}'{' arg=' + arg if arg else ''})")
        while True:
            sel = input("Select number (0 to skip): ").strip()
            if sel == "0" or sel == "":
                return [], []
            if not sel.isdigit():
                print("[!] Enter a number.")
                continue
            idx = int(sel) - 1
            if 0 <= idx < len(choices):
                choice = choices[idx]
                tokens = []
                flag = choice.get("flag", "")
                argname = choice.get("arg")
                if argname:
                    # prompt by arg type heuristics
                    if argname in ("file",):
                        val = self._prompt_filepath(f"Value for {argname}")
                    elif argname in ("ports", "port_spec"):
                        val = self._prompt_portspec(f"Value for {argname}")
                    elif argname in ("num", "number", "n"):
                        val = str(self._prompt_int(f"Value for {argname}", min_v=1))
                    elif argname in ("time",):
                        val = self._prompt_time(f"Value for {argname}")
                    elif argname in ("servers", "dns"):
                        val = self._prompt_csv(f"Value for {argname}")
                    else:
                        val = self._prompt_string(f"Value for {argname}")
                    if flag:
                        tokens = [flag, val]
                    else:
                        tokens = [val]
                else:
                    if flag:
                        tokens = [flag]
                    else:
                        val = choice.get("value")
                        tokens = [val] if val else []
                return tokens, [choice]
            print("[!] Invalid selection.")

    def _ask_multi_enum(self, placeholder_name: str, spec: dict) -> Tuple[List[str], List[dict]]:
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
            idxs = [s.strip() for s in sel.split(",") if s.strip()]
            valid = True
            for s in idxs:
                if not s.isdigit() or int(s) < 1 or int(s) > len(choices):
                    valid = False
                    break
            if not valid:
                print("[!] Invalid selection.")
                continue
            tokens = []
            chosen = []
            for s in idxs:
                choice = choices[int(s) - 1]
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
    # Main builder
    # -------------------------
    def _choose_service(self) -> Dict[str, Any]:
        print("\nAvailable Nmap configuration groups (services):")
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

    def build_command(self) -> Dict[str, Any]:
        """
        Interactively build nmap command. User can configure multiple services in sequence.
        Returns:
            {
                "cmd_list": [...],
                "cmd_quoted": "nmap ...",
                "manifest": <manifest>,
                "chosen": <list of chosen flags/meta>
            }
        """
        # We'll collect tokens incrementally.
        cmd_parts: List[str] = ["nmap"]
        chosen_choices = []

        print("\nConfigure Nmap scan. You will be able to add multiple groups (target, discovery, scan technique, output, etc.).")
        # Keep selecting services until user enters 0
        while True:
            service = self._choose_service()
            if service is None:
                break

            placeholders = service.get("placeholders", {})
            print(f"\nConfiguring: {service.get('label')}")

            for name, spec in placeholders.items():
                ptype = spec.get("type", "string")
                if ptype == "enum":
                    toks, chosen = self._ask_enum(name, spec)
                    if toks:
                        cmd_parts.extend(toks)
                        chosen_choices.extend(chosen)
                elif ptype == "multi_enum":
                    toks, chosen = self._ask_multi_enum(name, spec)
                    if toks:
                        cmd_parts.extend(toks)
                        chosen_choices.extend(chosen)
                elif ptype in ("target_multi", "target_multi", "target"):
                    val = self._prompt_hostspec(spec.get("prompt", "Targets"))
                    if val:
                        # targets may be multiple tokens (space separated)
                        cmd_parts.extend(val.split())
                elif ptype in ("portspec", "port", "port_optional", "port_spec"):
                    val = self._prompt_portspec(spec.get("prompt", "Ports"), allow_empty=True)
                    if val:
                        cmd_parts.extend([spec.get("flag","-p"), val] if spec.get("flag") else ["-p", val])
                elif ptype in ("file", "filepath"):
                    val = self._prompt_filepath(spec.get("prompt", "File"), allow_empty=True)
                    if val:
                        flag = spec.get("flag")
                        if flag:
                            cmd_parts.extend([flag, val])
                        else:
                            cmd_parts.append(val)
                elif ptype in ("time",):
                    val = self._prompt_time(spec.get("prompt", "Time value"), allow_empty=True)
                    if val:
                        # many time args include their flag via choice, so handled in enum/multi_enum
                        cmd_parts.append(val)
                else:
                    # fallback: simple string prompt
                    val = self._prompt_string(spec.get("prompt", name), allow_empty=True)
                    if val:
                        cmd_parts.append(val)

            # If service demands scope confirmation for high-risk flags, check later
            if service.get("requires_scope_confirmation"):
                # we'll check chosen_choices for high-risk items and confirm later
                pass

            # Ask user whether to continue adding other groups
            cont = self._ask_yes_no("Do you want to configure another Nmap group?", default=True)
            if not cont:
                break

        # Check for high-risk picks
        high_risk = [c for c in chosen_choices if c.get("risk") and str(c.get("risk")).lower() == "high"]
        if high_risk:
            print("\nWARNING: You selected high-risk options:")
            for c in high_risk:
                print("  -", c.get("label", c.get("id")))
            ok = self._ask_yes_no("Do you have authorization to run high-risk options?", default=False)
            if not ok:
                raise RuntimeError("User declined high-risk confirmation. Aborting.")

        # Final command cleaning: remove empty tokens
        cmd_parts = [p for p in cmd_parts if p and str(p).strip() != ""]

        # Quoted command for display
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        return {
            "cmd_list": cmd_parts,
            "cmd_quoted": cmd_quoted,
            "manifest": self.manifest,
            "chosen_choices": chosen_choices,
        }


# Quick manual test
if __name__ == "__main__":
    adapter = NmapAdapter(base_yaml_dir="yaml")
    res = adapter.build_command()
    print("\nGenerated command list:")
    print(res["cmd_list"])
    print("\nQuoted command:")
    print(res["cmd_quoted"])
