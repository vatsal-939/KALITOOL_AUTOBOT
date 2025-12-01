"""
tools/Masscan/masscan_adapter.py

Interactive adapter for Masscan. Loads yaml/Masscan/masscan.yaml via ManifestLoader,
prompts user for options, validates inputs using validators.*, builds command tokens,
displays the final command and can execute it (streams output).

Place this file at: tools/Masscan/masscan_adapter.py
"""

import shlex
import subprocess
from typing import Dict, Any, List, Tuple, Optional

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import network_validators, input_validators, file_validators

logger = get_logger(__name__)


class MasscanAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Masscan"
        self.command_name = "masscan"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        if not self.manifest:
            raise RuntimeError("masscan manifest not found")
        self.services = self.manifest.get("services", [])

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

    def _prompt_filepath(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            p = input(f"{prompt}: ").strip()
            if p == "" and allow_empty:
                return ""
            try:
                file_validators.validate_file_exists(p)
                return p
            except Exception as e:
                print(f"[!] invalid file: {e}")

    def _prompt_ip(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                network_validators.validate_ip(v)
                return v
            except Exception as e:
                print(f"[!] invalid IP/CIDR: {e}")

    def _prompt_mac(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                input_validators.validate_mac(v)
                return v
            except Exception as e:
                print(f"[!] invalid MAC address: {e}")

    def _prompt_positive_int(self, prompt: str, allow_empty: bool = False) -> int:
        while True:
            s = input(f"{prompt}: ").strip()
            if s == "" and allow_empty:
                return None
            if input_validators.validate_integer(s) and int(s) > 0:
                return int(s)
            print("[!] enter a positive integer")

    def _prompt_portspec(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            s = input(f"{prompt} (e.g. 80,443,1-65535 or U:53): ").strip()
            if s == "" and allow_empty:
                return ""
            if input_validators.validate_port_range(s):
                return s
            # accept UDP prefix form like U:53, or other masscan formats without strict validation
            if ":" in s or "-" in s or s.isdigit() or "," in s:
                return s
            print("[!] invalid port spec")

    def _prompt_targets(self, prompt: str, allow_empty: bool = False) -> List[str]:
        s = input(f"{prompt} (space or comma separated; can be CIDR/range/file tokens): ").strip()
        if s == "" and allow_empty:
            return []
        parts = [p.strip() for p in s.replace(",", " ").split() if p.strip()]
        return parts

    # -------------------------
    # Generic handler for multi flags (choices in manifest)
    # -------------------------
    def _ask_multi_enum(self, name: str, spec: dict) -> Tuple[List[str], List[dict]]:
        choices = spec.get("choices", [])
        if not choices:
            return [], []
        print(f"\nOptions for {name}:")
        for i, c in enumerate(choices, 1):
            print(f"  {i}. {c.get('label', c.get('id'))}  (flag='{c.get('flag','')}', arg='{c.get('arg','')}')")
        print("Select numbers comma-separated (0 to skip):")
        while True:
            sel = input("Selection: ").strip()
            if sel in ("0", ""):
                return [], []
            parts = [s.strip() for s in sel.split(",") if s.strip()]
            ok = True
            for p in parts:
                if not p.isdigit() or int(p) < 1 or int(p) > len(choices):
                    ok = False
                    break
            if not ok:
                print("[!] invalid selection")
                continue
            tokens = []
            chosen = []
            for p in parts:
                choice = choices[int(p) - 1]
                flag = choice.get("flag")
                argname = choice.get("arg")
                if argname:
                    # heuristics for arg prompts
                    if argname.lower() in ("file", "filename", "filepath"):
                        val = self._prompt_filepath(f"Value for {argname}", allow_empty=False)
                    elif "ip" in argname.lower():
                        val = self._prompt_ip(f"Value for {argname}", allow_empty=False)
                    elif "mac" in argname.lower():
                        val = self._prompt_mac(f"Value for {argname}", allow_empty=False)
                    elif argname.lower() in ("ports", "port_spec"):
                        val = self._prompt_portspec(f"Value for {argname}", allow_empty=False)
                    elif argname.lower() in ("rate", "number", "num"):
                        val = str(self._prompt_positive_int(f"Value for {argname}", allow_empty=False))
                    else:
                        val = self._prompt_string(f"Value for {argname}", allow_empty=False)
                    if flag:
                        tokens.extend([flag, val])
                    else:
                        tokens.append(val)
                else:
                    if flag:
                        tokens.append(flag)
                chosen.append(choice)
            return tokens, chosen

    # -------------------------
    # Service selection helper
    # -------------------------
    def _choose_service(self) -> Optional[Dict[str, Any]]:
        """Allow user to select which service to configure."""
        print("\nAvailable masscan configuration groups (services):")
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
        placeholders = service.get("placeholders", {}) or {}
        
        # simple handling by known placeholder names from manifest
        for name, spec in placeholders.items():
            ptype = spec.get("type", "string")
            flag = spec.get("flag")

            if ptype in ("target_multi", "targets"):
                targets = self._prompt_targets(spec.get("prompt", "Targets"), allow_empty=True)
                if targets:
                    cmd_parts.extend(targets)

            elif ptype == "filepath":
                val = self._prompt_filepath(spec.get("prompt", name), allow_empty=True)
                if val:
                    fl = flag or spec.get("flag") or "-iL"
                    cmd_parts.extend([fl, val])

            elif ptype == "string":
                val = self._prompt_string(spec.get("prompt", name), allow_empty=True)
                if val:
                    if flag:
                        cmd_parts.extend([flag, val])
                    else:
                        cmd_parts.append(val)

            elif ptype == "numeric":
                val = self._prompt_positive_int(spec.get("prompt", name), allow_empty=True)
                if val is not None:
                    if flag:
                        cmd_parts.extend([flag, str(val)])
                    else:
                        cmd_parts.append(str(val))

            elif ptype == "ip":
                val = self._prompt_ip(spec.get("prompt", name), allow_empty=True)
                if val:
                    cmd_parts.extend([flag, val])

            elif ptype == "mac":
                val = self._prompt_mac(spec.get("prompt", name), allow_empty=True)
                if val:
                    cmd_parts.extend([flag, val])

            elif ptype == "portspec" or name in ("port_spec", "port_specification", "port_spec"):
                val = self._prompt_portspec(spec.get("prompt", name), allow_empty=True)
                if val:
                    fl = spec.get("flag") or "-p"
                    cmd_parts.extend([fl, val])

            elif ptype in ("multi_enum", "enum"):
                toks, chosen = self._ask_multi_enum(name, spec)
                if toks:
                    cmd_parts.extend(toks)
                    chosen_meta.extend(chosen)

            elif ptype == "flag":
                use = self._ask_yes_no(f"Enable {name} ({spec.get('prompt','flag')})?", default=False)
                if use:
                    fl = flag or f"--{name}"
                    cmd_parts.append(fl)
                    chosen_meta.append({"flag": fl, "name": name})

            else:
                # fallback generic prompt
                val = self._prompt_string(spec.get("prompt", name), allow_empty=True)
                if val:
                    if flag:
                        cmd_parts.extend([flag, val])
                    else:
                        cmd_parts.append(val)

    # -------------------------
    # Main builder
    # -------------------------
    def build_command(self) -> Dict[str, Any]:
        cmd_parts: List[str] = ["masscan"]
        chosen_meta = []

        print("\nConfigure Masscan scan. You will be able to add multiple groups (targets, ports, adapter/network, rate/timing, output, etc.).")
        
        # Allow user to select which services to configure
        while True:
            service = self._choose_service()
            if service is None:
                break

            svc_label = service.get("label", service.get("id"))
            svc_desc = service.get("description", "")
            print(f"\n--- {svc_label} ---\n{svc_desc}\n")

            # Process the selected service
            self._process_service(service, cmd_parts, chosen_meta)

            # Ask user whether to continue adding other groups
            cont = self._ask_yes_no("Do you want to configure another masscan group?", default=True)
            if not cont:
                break

        # final cleaning
        cmd_parts = [p for p in cmd_parts if p and str(p).strip() != ""]
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        print("\nGenerated command:")
        print(cmd_quoted)

        # Confirm execution
        if self._ask_yes_no("Execute this masscan command now?", default=False):
            rc = self.execute_command(cmd_parts)
            print(f"[+] Process exited with code: {rc}")
        else:
            print("Execution skipped by user.")

        return {
            "cmd_list": cmd_parts,
            "cmd_quoted": cmd_quoted,
            "manifest": self.manifest,
            "chosen_meta": chosen_meta,
        }

    # -------------------------
    # Execution helper
    # -------------------------
    def execute_command(self, cmd_list: List[str]) -> int:
        logger.info("Executing: %s", " ".join(cmd_list))
        try:
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # stream stdout until process exits
            try:
                while True:
                    out = proc.stdout.readline()
                    if out:
                        print(out.rstrip())
                    elif proc.poll() is not None:
                        break
                # print remaining stderr
                err = proc.stderr.read()
                if err:
                    print(err.rstrip())
                return proc.returncode if proc.returncode is not None else 0
            except KeyboardInterrupt:
                proc.terminate()
                logger.warning("Execution interrupted by user.")
                return -1
        except FileNotFoundError:
            logger.error("masscan binary not found in PATH.")
            print("Error: 'masscan' not found. Is masscan installed and in PATH?")
            return -2
        except Exception as e:
            logger.error("Execution failed: %s", e)
            print(f"Execution failed: {e}")
            return -3


if __name__ == "__main__":
    adapter = MasscanAdapter(base_yaml_dir="yaml")
    result = adapter.build_command()
    print("\nResult command list:", result["cmd_list"])
    print("Quoted:", result["cmd_quoted"])
