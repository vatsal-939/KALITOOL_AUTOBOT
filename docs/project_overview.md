KaliTool AutoBot — Project Overview
===================================

What it is
----------
KaliTool AutoBot is a CLI orchestrator that builds and executes security-tool
commands from YAML manifests. It supports two manifest styles:
1) **Flag-based** (legacy, simple)
2) **Services/placeholder-based** (richer, used by most current tools) driven
   by tool-specific adapters.

Execution flow (high level)
---------------------------
1) `kalitool_autobot.py`
   - Reads `config.yaml`
   - Lists tools/commands from `yaml_dir`
   - Prompts user to pick tool + command
   - Invokes `Engine.run_tool(...)`

2) `engine.py`
   - Loads manifest via `ManifestLoader`
   - If manifest contains `services`: resolve and run a tool adapter
   - Else: use `UserInteraction` (flag-based) → `CommandBuilder` → confirm →
     execute → save output to `reports/{tool}/`
   - Adapter resolution:
     - Looks for `tools/{Tool}/{command}_adapter.py`
     - Tries adapter classes ending with `Adapter`
     - Falls back to module-level `run`, `execute`, or `build_command`

3) Validation
   - `validators/` modules provide input/file/network checks; used mainly by
     adapters and can be wired into interactions.

Manifest formats
----------------
Flag-based (legacy/simple)
- Required keys: `tool`, `command`, `description`, `flags` (list or dict)
- Flow: Interaction (asks per-flag) → CommandBuilder → execute

Services-based (current, richer)
- Keys: `tool_id`, `command_id`, `services` with `placeholders` and
  `command_template`
- Flow: Adapter handles prompts, validation, builds command, returns
  `cmd_list` / `cmd_quoted`
- Used by: Nmap/Ncat, Masscan, Ffuf, etc.

Adapters
--------
Location: `tools/{Tool}/{command}_adapter.py`
Responsibilities:
- Load manifest (via `ManifestLoader`)
- Prompt for placeholders / choices
- Validate inputs (using `validators/*`)
- Build final command (return `cmd_list` and/or `cmd_quoted`)
- Expose one of: `run()`, `execute()`, or `build_command()`

Current adapter examples
- `tools/Nmap/ncat_adapter.py`
- `tools/Nmap/nmap_adapter.py` (must expose run/execute/build_command)
- `tools/Masscan/masscan_adapter.py`
- `tools/Ffuf/ffuf_adapter.py`

Configuration (`config.yaml`)
-----------------------------
- `yaml_dir`: directory where manifests live (default `yaml`)
- `reports_dir`: where outputs are saved
- Logging: runtime/audit log paths and levels
- UX toggles: `ask_detailed_questions`, `auto_add_xml_output_for_parsers`, etc.

How to run
----------
1) Ensure dependencies (PyYAML, etc.) are installed.
2) From repo root:
   ```
   python kalitool_autobot.py
   ```
3) Choose tool (e.g., Nmap) and command (e.g., nmap or ncat).
4) Follow prompts; confirm execution. Output saved to `reports/{tool}/`.

Adding a new tool/command (services-based)
------------------------------------------
1) Create manifest at `yaml/{Tool}/{command}.yaml` with `services` and
   `placeholders`.
2) Create adapter at `tools/{Tool}/{command}_adapter.py` exposing run/execute/
   build_command that returns:
   ```
   {
     "cmd_list": ["binary", "-x", "arg"],
     "cmd_quoted": "binary -x arg"
   }
   ```
3) Use `validators/` for input/file/network safety.

Known limitations / notes
-------------------------
- `UserInteraction` supports only flag-based manifests; services-based
  manifests require adapters.
- If an adapter module exists but exposes no run/execute/build_command, the
  engine reports the missing entry point.
- Console banner is ASCII to avoid Windows encoding issues.

Key files
---------
- `kalitool_autobot.py`: CLI entrypoint
- `engine.py`: orchestration, adapter resolution, execution
- `manifest_loader.py`: loads/validates manifests
- `core/interaction.py`: flag-based prompting
- `core/command_builder.py`: builds shell-safe command strings
- `validators/*`: input/file/network validation helpers