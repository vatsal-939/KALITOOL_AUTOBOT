"""
zenmap_adapter.py
================

Interactive adapter for Zenmap. Loads yaml/Masscan/zenmap.yaml via ManifestLoader,
prompts user for options, validates inputs using validators.*, builds command tokens,
displays the final command and can execute it (streams output).

"""

import os
import shlex
import subprocess
from typing import Dict, Any, List

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import file_validators, input_validators, network_validators

logger = get_logger(__name__)


class ZenmapAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Nmap"
        self.command_name = "zenmap"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        # New schema: top-level services
        self.services = self.manifest.get("services", [])
        if not self.services:
            raise RuntimeError("zenmap manifest has no 'services' section")

    # -------------------------
    # Basic prompts & helpers
    # -------------------------
    def _ask_yes_no(self, question: str, default: bool = False) -> bool:
        default_hint = "Y/n" if default else "y/N"
        while True:
            r = input(f"{question} ({default_hint}): ").strip().lower()
            if r == "" and default:
                return True
            if r in ("y", "yes"):
                return True
            if r in ("n", "no"):
                return False
            print("[!] Please answer y or n.")

    def _ask_enum(self, placeholder_name: str, spec: dict):
        """
        Present single-choice enumerations. Returns (tokens, chosen_metadata).
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
                    # prompt for value
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

    def _ask_multi_enum(self, placeholder_name: str, spec: dict):
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

    def _prompt_string(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            if v != "" or allow_empty:
                return v

    def _prompt_filepath(self, prompt: str, allow_empty: bool = False, multiple: bool = False) -> List[str]:
        """
        Prompt for file path(s). If multiple=True allow comma-separated list.
        Returns list of validated paths (can be empty list).
        """
        while True:
            entry = input(f"{prompt}{' (comma-separated for multiple)' if multiple else ''}: ").strip()
            if entry == "" and allow_empty:
                return []
            items = [p.strip() for p in entry.split(",")] if multiple else [entry.strip()]
            invalid = []
            for p in items:
                if p == "":
                    continue
                try:
                    file_validators.validate_file_exists(p)
                except Exception:
                    invalid.append(p)
            if invalid:
                print("[!] These files were not found:", ", ".join(invalid))
                retry = self._ask_yes_no("Try again?")
                if retry:
                    continue
                else:
                    # return only the valid ones if user declines retry
                    return [p for p in items if p and p not in invalid]
            return [p for p in items if p]

    def _prompt_targets(self, prompt: str) -> List[str]:
        """
        Prompt for targets. Accepts Nmap-style target spec (can be multiple separated by spaces or commas).
        Returns list of tokens to append to the command.
        """
        s = input(f"{prompt} (e.g. scanme.nmap.org,192.168.0.0/24 or comma/space-separated list): ").strip()
        if not s:
            return []
        # split on whitespace or commas
        parts = []
        for chunk in s.replace(",", " ").split():
            if chunk:
                parts.append(chunk)
        return parts

    # -------------------------
    # Build command from manifest
    # -------------------------
    def build_command(self) -> Dict[str, Any]:
        """
        Interactively collect options according to the manifest and return:
          {
              "cmd_list": [...],
              "cmd_quoted": "zenmap ...",
              "manifest": <manifest>,
              "command_entry": <command_entry>
          }
        """
        cmd_parts: List[str] = ["zenmap"]
        services = self.services
        chosen_meta = []

        logger.info("Configuring zenmap")

        for service in services:
            label = service.get("label", service.get("id", "group"))
            print(f"\n-- {label} --")
            # walk placeholders inside this service
            placeholders = service.get("placeholders", {}) or {}
            for name, spec in placeholders.items():
                ptype = spec.get("type", "string")
                flag = spec.get("flag")  # optional
                prompt = spec.get("description") or spec.get("prompt") or name

                # Handle individual placeholder types
                if ptype == "enum":
                    toks, chosen = self._ask_enum(name, spec)
                    if toks:
                        cmd_parts.extend(toks)
                        chosen_meta.extend(chosen)
                    continue
                if ptype == "multi_enum":
                    toks, chosen = self._ask_multi_enum(name, spec)
                    if toks:
                        cmd_parts.extend(toks)
                        chosen_meta.extend(chosen)
                    continue
                if ptype in ("flag",):
                    use = self._ask_yes_no(f"Enable {name} ({prompt})?", default=False)
                    if use:
                        if flag:
                            cmd_parts.append(flag)
                        else:
                            cmd_parts.append(f"--{name}")
                        chosen_meta.append({"name": name, "spec": spec})
                elif ptype in ("filepath",):
                    multiple = bool(spec.get("multiple"))
                    allow_empty = not spec.get("required", False)
                    paths = self._prompt_filepath(prompt, allow_empty=allow_empty, multiple=multiple)
                    if paths:
                        for p in paths:
                            # use alias (short) if present
                            fl = spec.get("flag") or spec.get("alias") or "--" + name
                            cmd_parts.extend([fl, p])
                            chosen_meta.append({"name": name, "spec": spec, "value": p})
                elif ptype in ("string",):
                    val = self._prompt_string(prompt, allow_empty=not spec.get("required", False))
                    if val:
                        fl = spec.get("flag") or spec.get("alias")
                        if fl:
                            cmd_parts.extend([fl, val])
                        else:
                            # No flag - append raw arg (e.g., --nmap arguments or target)
                            cmd_parts.append(val)
                        chosen_meta.append({"name": name, "spec": spec, "value": val})
                elif ptype in ("target", "targets", "target_multi"):
                    targets = self._prompt_targets(prompt)
                    if targets:
                        cmd_parts.extend(targets)
                        chosen_meta.append({"name": name, "spec": spec, "value": targets})
                elif ptype in ("verbose",):
                    # allow user to repeat -v or use alias
                    use = self._ask_yes_no(f"Increase verbosity (repeatable)?", default=False)
                    if use:
                        count = self._prompt_int("How many times to repeat -v", min_v=1, max_v=10)
                        for _ in range(count):
                            cmd_parts.append(spec.get("flag", "-v"))
                        chosen_meta.append({"name": name, "spec": spec, "value": count})
                else:
                    # generic fallback
                    val = self._prompt_string(prompt, allow_empty=True)
                    if val:
                        if flag:
                            cmd_parts.extend([flag, val])
                        else:
                            cmd_parts.append(val)
                        chosen_meta.append({"name": name, "spec": spec, "value": val})

        # Clean tokens
        cmd_parts = [p for p in cmd_parts if p and str(p).strip() != ""]

        # Quoted string
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        return {
            "cmd_list": cmd_parts,
            "cmd_quoted": cmd_quoted,
            "manifest": self.manifest,
            "chosen_meta": chosen_meta,
        }

    def _prompt_int(self, prompt: str, min_v: int = None, max_v: int = None) -> int:
        while True:
            s = input(f"{prompt}: ").strip()
            if not s.isdigit():
                print("[!] Enter a positive integer.")
                continue
            v = int(s)
            if min_v is not None and v < min_v:
                print(f"[!] Minimum value is {min_v}")
                continue
            if max_v is not None and v > max_v:
                print(f"[!] Maximum value is {max_v}")
                continue
            return v

    # -------------------------
    # Execution helper
    # -------------------------
    def execute_command(self, cmd_list: List[str]) -> int:
        """
        Execute the command (list form) and stream stdout/stderr.
        Returns process returncode.
        """
        logger.info(f"Executing: {' '.join(cmd_list)}")
        try:
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # stream output lines
            while True:
                out = proc.stdout.readline()
                if out:
                    print(out.rstrip())
                elif proc.poll() is not None:
                    break
            # print remaining stderr
            stderr = proc.stderr.read()
            if stderr:
                print(stderr.rstrip())
            return proc.returncode if proc.returncode is not None else 0
        except FileNotFoundError:
            logger.error("zenmap executable not found in PATH.")
            print("Error: 'zenmap' not found. Is Zenmap installed and in PATH?")
            return -1
        except Exception as e:
            logger.error(f"Execution error: {e}")
            print(f"Execution failed: {e}")
            return -2


# -------------------------
# Module quick test
# -------------------------
if __name__ == "__main__":
    adapter = ZenmapAdapter(base_yaml_dir="yaml")
    result = adapter.build_command()
    print("\nGenerated command list:", result["cmd_list"])
    print("Quoted command:", result["cmd_quoted"])

    if adapter._ask_yes_no("Execute this command now?", default=False):
        rc = adapter.execute_command(result["cmd_list"])
        print(f"Process exited with code: {rc}")
    else:
        print("Execution cancelled by user.")
