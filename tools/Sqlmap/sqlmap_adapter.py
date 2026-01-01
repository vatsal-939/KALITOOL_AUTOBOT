"""
sqlmap_adapter.py
================

Interactive adapter for Sqlmap. Loads yaml/Masscan/sqlmap.yaml via ManifestLoader,
prompts user for options, validates inputs using validators.*, builds command tokens,
displays the final command and can execute it (streams output).

"""

import shlex
from typing import Dict, Any, List, Tuple

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import network_validators, input_validators, file_validators

logger = get_logger(__name__)


class SqlmapAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Sqlmap"
        self.command_name = "sqlmap"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        self.services = self.manifest.get("services", [])
        if not self.services:
            raise RuntimeError("sqlmap manifest has no 'services' section")

    # -------------------------
    # Basic prompts / helpers
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

    def _prompt_url(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                network_validators.validate_url(v)
                return v
            except ValueError as e:
                print(f"[!] invalid URL: {e}")

    def _prompt_int(self, prompt: str, min_v: int = None, max_v: int = None, allow_empty: bool = False) -> int:
        while True:
            s = input(f"{prompt}: ").strip()
            if s == "" and allow_empty:
                return None
            if not input_validators.validate_integer(s):
                print("[!] enter an integer")
                continue
            v = int(s)
            if min_v is not None and v < min_v:
                print(f"[!] must be >= {min_v}")
                continue
            if max_v is not None and v > max_v:
                print(f"[!] must be <= {max_v}")
                continue
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

    def _prompt_csv(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            s = input(f"{prompt} (comma-separated): ").strip()
            if s == "" and allow_empty:
                return ""
            parts = [p.strip() for p in s.split(",") if p.strip()]
            if not parts:
                print("[!] enter one or more values or leave blank")
                continue
            return ",".join(parts)

    # -------------------------
    # Choice handlers
    # -------------------------
    def _ask_enum(self, name: str, spec: dict) -> Tuple[List[str], List[dict]]:
        choices = spec.get("choices", [])
        if not choices:
            return [], []
        print(f"\nChoose {name}:")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c.get("id"))
            flag = c.get("flag", "")
            arg = c.get("arg", "")
            print(f"  {i}. {label}  (flag='{flag}'{' arg=' + arg if arg else ''})")
        while True:
            sel = input("Select number (0 to skip): ").strip()
            if sel in ("0", ""):
                return [], []
            if not sel.isdigit():
                print("[!] enter a number")
                continue
            idx = int(sel) - 1
            if 0 <= idx < len(choices):
                choice = choices[idx]
                tokens = []
                flag = choice.get("flag", "")
                argname = choice.get("arg")
                if argname:
                    # dispatch prompts by arg type heuristics
                    if "URL" in argname.upper():
                        val = self._prompt_url(f"Enter value for {argname}")
                    elif argname.lower() in ("n", "num", "level", "risk"):
                        val = str(self._prompt_int(f"Enter value for {argname}", min_v=1))
                    elif "file" in argname.lower():
                        val = self._prompt_filepath(f"Enter path for {argname}")
                    elif "," in argname or argname.lower().endswith("s"):
                        val = self._prompt_csv(f"Enter comma-separated {argname}")
                    else:
                        val = self._prompt_string(f"Enter value for {argname}")
                    if flag:
                        tokens = [flag, val]
                    else:
                        tokens = [val]
                else:
                    if flag:
                        tokens = [flag]
                    else:
                        tokens = []
                return tokens, [choice]
            print("[!] invalid selection")

    def _ask_multi_enum(self, name: str, spec: dict) -> Tuple[List[str], List[dict]]:
        choices = spec.get("choices", [])
        if not choices:
            return [], []
        print(f"\nMulti-select for {name} (comma-separated numbers, 0 to skip):")
        for i, c in enumerate(choices, 1):
            print(f"  {i}. {c.get('label', c.get('id'))} (flag='{c.get('flag','')}')")
        while True:
            sel = input("Select numbers: ").strip()
            if sel in ("0", ""):
                return [], []
            parts = [s.strip() for s in sel.split(",") if s.strip()]
            ok = True
            for p in parts:
                if not p.isdigit() or int(p) < 1 or int(p) > len(choices):
                    ok = False
                    break
            if not ok:
                print("[!] invalid selection, try again")
                continue
            tokens = []
            chosen = []
            for p in parts:
                choice = choices[int(p) - 1]
                if "arg" in choice:
                    toks, ch = self._ask_enum(f"{name}:{choice.get('label')}", {"choices": [choice]})
                    tokens.extend(toks)
                    chosen.extend(ch)
                else:
                    flag = choice.get("flag", "")
                    if flag:
                        tokens.append(flag)
                    chosen.append(choice)
            return tokens, chosen

    # -------------------------
    # Main build routine
    # -------------------------
    def build_command(self) -> Dict[str, Any]:
        cmd_parts: List[str] = ["sqlmap"]
        chosen_choices = []

        print("\nConfigure sqlmap command. You'll be asked grouped questions based on the manifest.\n")
        for service in self.services:
            print(f"--- {service.get('label')} ---\n{service.get('description','')}\n")
            placeholders = service.get("placeholders", {}) or {}
            for pname, spec in placeholders.items():
                ptype = spec.get("type", "string")
                if ptype == "enum":
                    toks, chosen = self._ask_enum(pname, spec)
                    if toks:
                        cmd_parts.extend(toks)
                        chosen_choices.extend(chosen)
                elif ptype == "multi_enum":
                    toks, chosen = self._ask_multi_enum(pname, spec)
                    if toks:
                        cmd_parts.extend(toks)
                        chosen_choices.extend(chosen)
                elif ptype in ("targets", "target", "url"):
                    # manifest used multi_enum for -u and -g; but support a fallback
                    v = self._prompt_url(spec.get("prompt", "Target URL (-u)"), allow_empty=True)
                    if v:
                        cmd_parts.extend(["-u", v])
                elif ptype == "string":
                    v = self._prompt_string(spec.get("prompt", pname), allow_empty=True)
                    if v:
                        flag = spec.get("flag")
                        if flag:
                            cmd_parts.extend([flag, v])
                        else:
                            cmd_parts.append(v)
                else:
                    # generic fallback
                    v = self._prompt_string(spec.get("prompt", pname), allow_empty=True)
                    if v:
                        flag = spec.get("flag")
                        if flag:
                            cmd_parts.extend([flag, v])
                        else:
                            cmd_parts.append(v)

        # High-risk confirmation
        high_risk = []
        for svc in self.services:
            placeholders = svc.get("placeholders", {}) or {}
            for _, spec in placeholders.items():
                # collect any chosen choice in chosen_choices matching risk=high
                # chosen_choices contains dicts from manifest choices with optional "risk"
                for c in chosen_choices:
                    if c.get("risk") and str(c.get("risk")).lower() == "high":
                        high_risk.append(c)
        if high_risk:
            print("\nWARNING: You selected high-risk sqlmap options (dump, os-shell, os-pwn etc.).")
            ok = self._ask_yes_no("Do you have explicit authorization and want to continue?", default=False)
            if not ok:
                raise RuntimeError("User declined confirmation for high-risk actions.")

        # Final cleanup and quote
        cmd_parts = [p for p in cmd_parts if p and str(p).strip() != ""]
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        return {
            "cmd_list": cmd_parts,
            "cmd_quoted": cmd_quoted,
            "manifest": self.manifest,
            "chosen_choices": chosen_choices,
        }


if __name__ == "__main__":
    adapter = SqlmapAdapter(base_yaml_dir="yaml")
    res = adapter.build_command()
    print("\nGenerated command list:", res["cmd_list"])
    print("Quoted command:", res["cmd_quoted"])
