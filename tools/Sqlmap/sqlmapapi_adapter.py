"""
sqlmapapi_adapter.py
================

Interactive adapter for Sqlmapapi. Loads yaml/Masscan/sqlmapapi.yaml via ManifestLoader,
prompts user for options, validates inputs using validators.*, builds command tokens,
displays the final command and can execute it (streams output).

"""

import shlex
import subprocess
from typing import Dict, Any, List

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import network_validators, file_validators, input_validators

logger = get_logger(__name__)


class SqlmapApiAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Sqlmap"
        self.command_name = "sqlmapapi"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        if not self.manifest:
            raise RuntimeError("sqlmapapi manifest not found")
        # manifest expects top-level 'services'
        self.services = self.manifest.get("services", [])

    # -------------------------
    # small helpers
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

    def _prompt_host(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                network_validators.validate_host_or_ip(v)
                return v
            except Exception as e:
                print(f"[!] invalid host: {e}")

    def _prompt_port(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt} (1-65535): ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                network_validators.validate_port(v)
                return v
            except Exception as e:
                print(f"[!] invalid port: {e}")

    def _prompt_string(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            if v != "" or allow_empty:
                return v

    def _prompt_filepath(self, prompt: str, allow_empty: bool = True) -> str:
        while True:
            v = input(f"{prompt}: ").strip()
            if v == "" and allow_empty:
                return ""
            try:
                file_validators.validate_file_exists(v)
                return v
            except Exception as e:
                print(f"[!] invalid file: {e}")

    # -------------------------
    # Manifest-driven builder
    # -------------------------
    def build_command(self) -> Dict[str, Any]:
        """
        Interactively build sqlmapapi command according to manifest and return:
        { "cmd_list": [...], "cmd_quoted": "...", "manifest": <manifest> }
        """
        # find mode service (manifest structured with a mode service)
        cmd_parts: List[str] = ["sqlmapapi"]
        chosen_meta = []

        # Try to find the "mode" service first (common manifest structure)
        mode_service = None
        for s in self.services:
            if s.get("id") == "mode":
                mode_service = s
                break
        if not mode_service:
            # fallback to first service
            mode_service = self.services[0] if self.services else None

        if not mode_service:
            raise RuntimeError("sqlmapapi manifest has no services")

        print("\n--- sqlmapapi: mode selection ---")
        # mode_flag placeholder (enum server/client)
        placeholders = mode_service.get("placeholders", {})
        mode_spec = placeholders.get("mode_flag", {})
        mode_choice = None
        if mode_spec:
            choices = mode_spec.get("choices", [])
            # show choices
            for i, c in enumerate(choices, 1):
                print(f"  {i}. {c.get('label', c.get('id'))}")
            while True:
                sel = input("Select mode number (1=server, 2=client): ").strip()
                if not sel.isdigit():
                    print("[!] Enter a number")
                    continue
                idx = int(sel) - 1
                if 0 <= idx < len(choices):
                    mode_choice = choices[idx]
                    break
                print("[!] Invalid selection")

            # add server/client flag (either short -s/-c or full value if present)
            if mode_choice.get("flag"):
                cmd_parts.append(mode_choice["flag"])
            elif mode_choice.get("value"):
                cmd_parts.append(mode_choice["value"])
            chosen_meta.append({"mode": mode_choice.get("id")})

        # host and port placeholders
        host_port_spec = placeholders.get("host_and_port", {})
        # host_and_port was modeled as multi_enum (host, port)
        if host_port_spec:
            hp_choices = host_port_spec.get("choices", [])
            # for each of host/port prompt if present
            for choice in hp_choices:
                if choice.get("id") == "host":
                    default_host = choice.get("default", "127.0.0.1")
                    use_default = self._ask_yes_no(f"Use host [{default_host}]?", default=True)
                    if use_default:
                        host_val = default_host
                    else:
                        host_val = self._prompt_host("Enter API host", allow_empty=False)
                    if host_val:
                        cmd_parts.extend([choice.get("flag", "-H"), host_val])
                        chosen_meta.append({"host": host_val})
                if choice.get("id") == "port":
                    default_port = choice.get("default", "8775")
                    use_default = self._ask_yes_no(f"Use port [{default_port}]?", default=True)
                    if use_default:
                        port_val = default_port
                    else:
                        port_val = self._prompt_port("Enter API port", allow_empty=False)
                    if port_val:
                        cmd_parts.extend([choice.get("flag", "-p"), str(port_val)])
                        chosen_meta.append({"port": port_val})

        # adapter option
        adapter_spec = placeholders.get("adapter", {})
        if adapter_spec:
            # present adapter choices if provided
            choices = adapter_spec.get("choices", [])
            if choices:
                print("\nAdapter choices:")
                for i, c in enumerate(choices, 1):
                    print(f"  {i}. {c.get('label', c.get('id'))} (default: {c.get('value')})")
                sel = input("Select adapter number or press Enter to use default: ").strip()
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(choices):
                        chosen = choices[idx]
                        arg = chosen.get("arg")
                        val = chosen.get("value") or self._prompt_string(f"Value for {arg}", allow_empty=False)
                        cmd_parts.extend([chosen.get("flag", "--adapter"), val])
                        chosen_meta.append({"adapter": val})
                else:
                    # use default if present
                    default_choice = next((c for c in choices if c.get("value")), None)
                    if default_choice:
                        cmd_parts.extend([default_choice.get("flag", "--adapter"), default_choice.get("value")])
                        chosen_meta.append({"adapter": default_choice.get("value")})

        # database option
        db_spec = placeholders.get("database", {})
        if db_spec:
            use_db = self._ask_yes_no("Provide an IPC database filepath? (recommended to skip unless needed)", default=False)
            if use_db:
                db_path = self._prompt_filepath("Enter IPC database filepath", allow_empty=False)
                if db_path:
                    cmd_parts.extend([db_spec.get("flag", "--database"), db_path])
                    chosen_meta.append({"database": db_path})

        # username/password
        auth_spec = placeholders.get("auth", {})
        if auth_spec:
            # username
            user_choice = next((c for c in auth_spec.get("choices", []) if c.get("id") == "username"), None)
            pass_choice = next((c for c in auth_spec.get("choices", []) if c.get("id") == "password"), None)
            if user_choice:
                u = self._prompt_string("Basic auth username (leave blank to skip)", allow_empty=True)
                if u:
                    cmd_parts.extend([user_choice.get("flag", "--username"), u])
                    chosen_meta.append({"username": u})
            if pass_choice:
                p = self._prompt_string("Basic auth password (leave blank to skip)", allow_empty=True)
                if p:
                    cmd_parts.extend([pass_choice.get("flag", "--password"), p])
                    chosen_meta.append({"password": "******"})

        # misc service (help)
        misc = next((s for s in self.services if s.get("id") == "misc"), None)
        if misc:
            placeholders = misc.get("placeholders", {}) or {}
            misc_flags = placeholders.get("misc_flags", {})
            choices = misc_flags.get("choices", []) if misc_flags else []
            for c in choices:
                if c.get("id") == "help":
                    use_help = self._ask_yes_no("Show help (-h)?", default=False)
                    if use_help:
                        cmd_parts.append(c.get("flag", "-h"))
                        chosen_meta.append({"help": True})

        # Finalize
        cmd_parts = [p for p in cmd_parts if p and str(p).strip() != ""]
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

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
        """
        Executes the command (list form) and streams stdout/stderr.
        Returns process returncode.
        """
        logger.info("Executing: %s", " ".join(cmd_list))
        try:
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # stream stdout and stderr lines until completion
            try:
                while True:
                    out = proc.stdout.readline()
                    if out:
                        print(out.rstrip())
                    elif proc.poll() is not None:
                        break
                err = proc.stderr.read()
                if err:
                    print(err.rstrip())
                return proc.returncode if proc.returncode is not None else 0
            except KeyboardInterrupt:
                proc.terminate()
                logger.warning("Execution interrupted by user.")
                return -1
        except FileNotFoundError:
            logger.error("sqlmapapi binary not found in PATH.")
            print("Error: 'sqlmapapi' not found. Is it installed and available in PATH?")
            return -2
        except Exception as e:
            logger.error("Execution failed: %s", e)
            print(f"Execution failed: {e}")
            return -3


if __name__ == "__main__":
    adapter = SqlmapApiAdapter(base_yaml_dir="yaml")
    built = adapter.build_command()
    print("\nCommand:", built["cmd_quoted"])
    if adapter._ask_yes_no("Execute now?", default=False):
        rc = adapter.execute_command(built["cmd_list"])
        print("Return code:", rc)
    else:
        print("Execution cancelled.")
