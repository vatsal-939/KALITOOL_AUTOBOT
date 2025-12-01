"""
tools/Ffuf/ffuf_adapter.py

Interactive adapter for ffuf. Loads yaml/Ffuf/ffuf.yaml via ManifestLoader,
prompts user for options, validates inputs using validators.*, builds command tokens,
displays the final command and can execute it (streams output).

Place this file at: tools/Ffuf/ffuf_adapter.py
"""

import shlex
import subprocess
from typing import Dict, Any, List, Tuple, Optional

from manifest_loader import ManifestLoader
from core.logger import get_logger
from validators import file_validators, input_validators, network_validators

logger = get_logger(__name__)


class FfufAdapter:
    def __init__(self, base_yaml_dir: str = "yaml"):
        self.loader = ManifestLoader(base_yaml_dir)
        self.tool_name = "Ffuf"
        self.command_name = "ffuf"
        self.manifest = self.loader.load_manifest(self.tool_name, self.command_name)
        if not self.manifest:
            raise RuntimeError("ffuf manifest not found")
        # manifest services (http_options, general_options, matcher_options, filter_options, input_options, output_options)
        self.services = self.manifest.get("services", [])

    # -------------------------
    # Prompt helpers
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

    def _prompt_numeric(self, prompt: str, allow_empty: bool = False) -> Optional[int]:
        while True:
            s = input(f"{prompt}: ").strip()
            if s == "" and allow_empty:
                return None
            if input_validators.validate_integer(s):
                return int(s)
            try:
                # accept floats for some numeric flags (e.g. delay)
                float(s)
                return s  # caller may accept string floats
            except Exception:
                print("[!] enter a valid number")

    def _prompt_delay(self, prompt: str, allow_empty: bool = False) -> str:
        while True:
            s = input(f"{prompt} (e.g. 0.1 or 0.1-2.0): ").strip()
            if s == "" and allow_empty:
                return ""
            # basic validation: number or range with dash
            if "-" in s:
                parts = s.split("-", 1)
                try:
                    float(parts[0]); float(parts[1])
                    return s
                except Exception:
                    print("[!] invalid range format")
                    continue
            try:
                float(s)
                return s
            except Exception:
                print("[!] invalid value")

    def _prompt_headers(self) -> List[str]:
        headers = []
        while True:
            h = input("Add header (-H 'Name: Value') (blank to stop): ").strip()
            if not h:
                break
            headers.extend(["-H", h])
        return headers

    def _prompt_multi_choice(self, spec: dict) -> Tuple[List[str], List[dict]]:
        """
        Generic handler for multi_enum or multi-choice placeholders.
        Returns (tokens_list, chosen_meta)
        """
        choices = spec.get("choices", [])
        if not choices:
            return [], []
        print("\nOptions:")
        for i, c in enumerate(choices, 1):
            label = c.get("label", c.get("id"))
            arg = c.get("arg")
            print(f"  {i}. {label}" + (f" (arg: {arg})" if arg else ""))
        print("Select numbers comma-separated (0 = skip).")
        while True:
            sel = input("Selection: ").strip()
            if sel in ("", "0"):
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
                chosen.append(choice)
                flag = choice.get("flag")
                argname = choice.get("arg")
                if argname:
                    # prompt by heuristics
                    if "file" in argname.lower():
                        val = self._prompt_filepath(f"Enter value for {argname}", allow_empty=False)
                    elif argname.lower() in ("string", "scraperfile", "scrapers"):
                        val = self._prompt_string(f"Enter value for {argname}", allow_empty=False)
                    else:
                        val = self._prompt_string(f"Enter value for {argname}", allow_empty=False)
                    if flag:
                        tokens.extend([flag, val])
                    else:
                        tokens.append(val)
                else:
                    if flag:
                        tokens.append(flag)
            return tokens, chosen

    # -------------------------
    # Service-specific handlers
    # -------------------------
    def _handle_http_options(self, placeholders: dict, cmd_parts: List[str], chosen_meta: List[dict]):
        # headers
        if "header" in placeholders:
            hdrs = self._prompt_headers()
            if hdrs:
                cmd_parts.extend(hdrs)
                chosen_meta.append({"header_count": int(len(hdrs) / 2)})
        # method
        if "method" in placeholders:
            m = self._prompt_string("HTTP method (-X) (press Enter to skip)", allow_empty=True)
            if m:
                cmd_parts.extend(["-X", m])
        # cookie
        if "cookie" in placeholders:
            v = self._prompt_string("Cookie data (-b) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-b", v])
        # cert/key
        if "client_cert" in placeholders:
            v = self._prompt_filepath("Client cert path (-cc) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-cc", v])
        if "client_key" in placeholders:
            v = self._prompt_filepath("Client key path (-ck) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-ck", v])
        # post data
        if "post_data" in placeholders:
            v = self._prompt_string("POST data (-d) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-d", v])
        # http2, ignore-body, follow redirects, raw
        for flag_name in ("http2", "ignore_body", "follow_redirects", "raw_uri", "recursion"):
            if flag_name in placeholders:
                flag = placeholders[flag_name].get("flag")
                if self._ask_yes_no(f"Enable {flag_name.replace('_',' ')} ({flag})?", default=False):
                    cmd_parts.append(flag)
        # recursion depth
        if "recursion_depth" in placeholders:
            v = self._prompt_numeric("Recursion depth (-recursion-depth) (press Enter to skip)", allow_empty=True)
            if v is not None:
                cmd_parts.extend(["-recursion-depth", str(v)])
        # recursion strategy
        if "recursion_strategy" in placeholders:
            strat = self._prompt_string("Recursion strategy (-recursion-strategy) [default|greedy] (press Enter to skip)", allow_empty=True)
            if strat:
                cmd_parts.extend(["-recursion-strategy", strat])
        # replay-proxy, sni, timeout, url, proxy
        for opt in ("replay_proxy", "sni", "timeout", "url", "proxy"):
            if opt in placeholders:
                key = placeholders[opt].get("flag")
                if opt == "timeout":
                    val = self._prompt_numeric("Timeout seconds (-timeout) (press Enter to skip)", allow_empty=True)
                    if val is not None:
                        cmd_parts.extend([key, str(val)])
                elif opt in ("url", "proxy", "sni", "replay_proxy"):
                    val = self._prompt_string(f"{placeholders[opt].get('prompt')} (press Enter to skip)", allow_empty=True)
                    if val:
                        cmd_parts.extend([key, val])

    def _handle_general_options(self, placeholders: dict, cmd_parts: List[str], chosen_meta: List[dict]):
        # many flags; handle primary ones
        if "version" in placeholders and self._ask_yes_no("Show version (-V)?", default=False):
            cmd_parts.append("-V")
        if "autocalibrate" in placeholders and self._ask_yes_no("Auto-calibrate filtering (-ac)?", default=False):
            cmd_parts.append("-ac")
        if "autocalibrate_custom" in placeholders:
            toks, chosen = self._prompt_multi_choice(placeholders["autocalibrate_custom"])
            if toks:
                cmd_parts.extend(toks)
                chosen_meta.extend(chosen)
        if "perhost_autocal" in placeholders and self._ask_yes_no("Per-host auto-calibration (-ach)?", default=False):
            cmd_parts.append("-ach")
        if "autocal_keyword" in placeholders:
            v = self._prompt_string("Autocalibration keyword (-ack) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-ack", v])
        if "colorize" in placeholders and self._ask_yes_no("Colorize output (-c)?", default=False):
            cmd_parts.append("-c")
        if "config_file" in placeholders:
            v = self._prompt_filepath("Load configuration file (-config) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-config", v])
        if "json_out" in placeholders and self._ask_yes_no("JSON output (-json)?", default=False):
            cmd_parts.append("-json")
        if "maxtime" in placeholders:
            v = self._prompt_numeric("Max running time seconds (-maxtime) (press Enter to skip)", allow_empty=True)
            if v is not None:
                cmd_parts.extend(["-maxtime", str(v)])
        if "maxtime_job" in placeholders:
            v = self._prompt_numeric("Max running time per job (-maxtime-job) (press Enter to skip)", allow_empty=True)
            if v is not None:
                cmd_parts.extend(["-maxtime-job", str(v)])
        if "noninteractive" in placeholders and self._ask_yes_no("Disable interactive console (-noninteractive)?", default=False):
            cmd_parts.append("-noninteractive")
        if "delay" in placeholders:
            v = self._prompt_delay("Delay between requests (-p) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-p", v])
        if "rate" in placeholders:
            v = self._prompt_numeric("Requests per second (-rate) (press Enter to skip)", allow_empty=True)
            if v is not None:
                cmd_parts.extend(["-rate", str(v)])
        if "silent" in placeholders and self._ask_yes_no("Silent mode (-s)?", default=False):
            cmd_parts.append("-s")
        if "stop_all_errors" in placeholders and self._ask_yes_no("Stop on all error cases (-sa)?", default=False):
            cmd_parts.append("-sa")
        if "scraperfile" in placeholders:
            v = self._prompt_filepath("Custom scraper file path (-scraperfile) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-scraperfile", v])
        if "scrapers" in placeholders:
            v = self._prompt_string("Active scraper groups (-scrapers) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-scrapers", v])
        if "stop_spurious" in placeholders and self._ask_yes_no("Stop on spurious errors (-se)?", default=False):
            cmd_parts.append("-se")
        if "search_history" in placeholders:
            v = self._prompt_string("Search FFUFHASH from history (-search) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-search", v])
        if "stop_on_403" in placeholders and self._ask_yes_no("Stop when >95% responses are 403 (-sf)?", default=False):
            cmd_parts.append("-sf")
        if "threads" in placeholders:
            v = self._prompt_numeric("Number of concurrent threads (-t) (press Enter to skip)", allow_empty=True)
            if v is not None:
                cmd_parts.extend(["-t", str(v)])
        if "verbose" in placeholders and self._ask_yes_no("Verbose output (-v)?", default=False):
            cmd_parts.append("-v")

    def _handle_matcher_options(self, placeholders: dict, cmd_parts: List[str], chosen_meta: List[dict]):
        if "match_codes" in placeholders:
            v = self._prompt_string("Match HTTP status codes or 'all' (-mc) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-mc", v])
        if "match_lines" in placeholders:
            v = self._prompt_string("Match number of lines (-ml) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-ml", v])
        if "match_mode" in placeholders:
            m = self._prompt_string("Matcher set operator (-mmode) [or|and] (press Enter to skip)", allow_empty=True)
            if m:
                cmd_parts.extend(["-mmode", m])
        if "match_regex" in placeholders:
            v = self._prompt_string("Match regexp (-mr) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-mr", v])
        if "match_size" in placeholders:
            v = self._prompt_string("Match response size (-ms) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-ms", v])
        if "match_time" in placeholders:
            v = self._prompt_string("Match time to first byte (-mt) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-mt", v])
        if "match_words" in placeholders:
            v = self._prompt_string("Match number of words (-mw) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-mw", v])

    def _handle_filter_options(self, placeholders: dict, cmd_parts: List[str], chosen_meta: List[dict]):
        if "filter_codes" in placeholders:
            v = self._prompt_string("Filter HTTP status codes (-fc) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-fc", v])
        if "filter_lines" in placeholders:
            v = self._prompt_string("Filter by lines (-fl) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-fl", v])
        if "filter_mode" in placeholders:
            m = self._prompt_string("Filter operator (-fmode) [or|and] (press Enter to skip)", allow_empty=True)
            if m:
                cmd_parts.extend(["-fmode", m])
        if "filter_regex" in placeholders:
            v = self._prompt_string("Filter regexp (-fr) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-fr", v])
        if "filter_size" in placeholders:
            v = self._prompt_string("Filter response size (-fs) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-fs", v])
        if "filter_time" in placeholders:
            v = self._prompt_string("Filter by time (-ft) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-ft", v])
        if "filter_words" in placeholders:
            v = self._prompt_string("Filter by words (-fw) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-fw", v])

    def _handle_input_options(self, placeholders: dict, cmd_parts: List[str], chosen_meta: List[dict]):
        if "dirsearch_mode" in placeholders and self._ask_yes_no("Enable DirSearch compatibility (-D)?", default=False):
            cmd_parts.append("-D")
        if "extensions" in placeholders:
            v = self._prompt_string("Extensions (-e) comma-separated (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-e", v])
        if "encoders" in placeholders:
            v = self._prompt_string("Encoders (-enc) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-enc", v])
        if "ignore_comments" in placeholders and self._ask_yes_no("Ignore wordlist comments (-ic)?", default=False):
            cmd_parts.append("-ic")
        if "input_cmd" in placeholders:
            v = self._prompt_string("Command producing input (-input-cmd) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-input-cmd", v])
        if "input_num" in placeholders:
            v = self._prompt_numeric("Number of inputs (-input-num) (press Enter to skip)", allow_empty=True)
            if v is not None:
                cmd_parts.extend(["-input-num", str(v)])
        if "input_shell" in placeholders:
            v = self._prompt_string("Shell to run input command (-input-shell) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-input-shell", v])
        if "mode" in placeholders:
            m = self._prompt_string("Mode (-mode) [clusterbomb|pitchfork|sniper] (press Enter to skip)", allow_empty=True)
            if m:
                cmd_parts.extend(["-mode", m])
        if "raw_request" in placeholders:
            v = self._prompt_filepath("Raw request file (-request) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-request", v])
        if "request_proto" in placeholders:
            v = self._prompt_string("Raw request protocol (-request-proto) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-request-proto", v])
        if "wordlist" in placeholders:
            v = self._prompt_string("Wordlist file path (-w) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-w", v])

    def _handle_output_options(self, placeholders: dict, cmd_parts: List[str], chosen_meta: List[dict]):
        if "debug_log" in placeholders:
            v = self._prompt_filepath("Debug log path (-debug-log) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-debug-log", v])
        if "output_file" in placeholders:
            v = self._prompt_filepath("Output file (-o) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-o", v])
        if "output_dir" in placeholders:
            v = self._prompt_string("Output directory (-od) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-od", v])
        if "output_format" in placeholders:
            v = self._prompt_string("Output format(s) (-of) (json,ejson,html,md,csv,ecsv or all) (press Enter to skip)", allow_empty=True)
            if v:
                cmd_parts.extend(["-of", v])
        if "output_require_results" in placeholders and self._ask_yes_no("Don't create file if no results (-or)?", default=False):
            cmd_parts.append("-or")

    # -------------------------
    # Service selection helper
    # -------------------------
    def _choose_service(self) -> Optional[Dict[str, Any]]:
        """Allow user to select which service to configure."""
        print("\nAvailable ffuf configuration groups (services):")
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

    def _process_service(self, svc: Dict[str, Any], cmd_parts: List[str], chosen_meta: List[dict]):
        """Process a single selected service and add flags to cmd_parts."""
        svc_id = svc.get("id")
        placeholders = svc.get("placeholders", {}) or {}
        
        if svc_id == "http_options":
            self._handle_http_options(placeholders, cmd_parts, chosen_meta)
        elif svc_id == "general_options":
            self._handle_general_options(placeholders, cmd_parts, chosen_meta)
        elif svc_id == "matcher_options":
            self._handle_matcher_options(placeholders, cmd_parts, chosen_meta)
        elif svc_id == "filter_options":
            self._handle_filter_options(placeholders, cmd_parts, chosen_meta)
        elif svc_id == "input_options":
            self._handle_input_options(placeholders, cmd_parts, chosen_meta)
        elif svc_id == "output_options":
            self._handle_output_options(placeholders, cmd_parts, chosen_meta)
        else:
            # unknown service: try to prompt generically for its placeholders
            for name, spec in placeholders.items():
                if spec.get("type") in ("flag",):
                    if self._ask_yes_no(f"Enable {name}?", default=False):
                        cmd_parts.append(spec.get("flag", f"--{name}"))
                else:
                    v = self._prompt_string(spec.get("prompt", name), allow_empty=True)
                    if v:
                        fl = spec.get("flag")
                        if fl:
                            cmd_parts.extend([fl, v])
                        else:
                            cmd_parts.append(v)

    # -------------------------
    # Main build routine
    # -------------------------
    def build_command(self) -> Dict[str, Any]:
        cmd_parts: List[str] = ["ffuf"]
        chosen_meta: List[dict] = []

        if not self.services:
            raise RuntimeError("ffuf manifest contains no services")

        print("\nConfigure ffuf command. You will be able to add multiple groups (HTTP options, general options, matchers, filters, input, output, etc.).")
        
        # Allow user to select which services to configure
        while True:
            service = self._choose_service()
            if service is None:
                break

            print(f"\nConfiguring: {service.get('label')}")

            # Process the selected service
            self._process_service(service, cmd_parts, chosen_meta)

            # Ask user whether to continue adding other groups
            cont = self._ask_yes_no("Do you want to configure another ffuf group?", default=True)
            if not cont:
                break

        # final cleaning & quoting
        cmd_parts = [p for p in cmd_parts if p and str(p).strip() != ""]
        cmd_quoted = " ".join(shlex.quote(p) for p in cmd_parts)

        print("\nGenerated ffuf command:")
        print(cmd_quoted)

        # Ask to execute
        if self._ask_yes_no("Execute this ffuf command now?", default=False):
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
            try:
                # stream stdout
                while True:
                    out_line = proc.stdout.readline()
                    if out_line:
                        print(out_line.rstrip())
                    elif proc.poll() is not None:
                        break
                # print remaining stderr
                stderr = proc.stderr.read()
                if stderr:
                    print(stderr.rstrip())
                return proc.returncode if proc.returncode is not None else 0
            except KeyboardInterrupt:
                proc.terminate()
                logger.warning("Execution interrupted.")
                return -1
        except FileNotFoundError:
            logger.error("ffuf binary not found in PATH.")
            print("Error: 'ffuf' not found. Is ffuf installed and available in PATH?")
            return -2
        except Exception as e:
            logger.error("Execution failed: %s", e)
            print(f"Execution failed: {e}")
            return -3


if __name__ == "__main__":
    adapter = FfufAdapter(base_yaml_dir="yaml")
    result = adapter.build_command()
    print("\nCommand list:", result["cmd_list"])
    print("Quoted:", result["cmd_quoted"])
