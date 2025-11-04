import subprocess
import yaml
import os
from manifest_loader import ManifestLoader
from core.command_builder import CommandBuilder
from core.interaction import UserInteraction as Interaction
# from core.logger import Logger
from validators import input_validators, file_validators, network_validators
from core.logger import get_logger as Logger

class Engine:
    """
    Core engine for KaliTool AutoBot.
    Coordinates YAML loading, user interaction, command construction, and execution.
    """

    def __init__(self, config_path="config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = Logger("KaliToolAutoBot")
        self.yaml_dir = self.config["yaml_dir"]

    # -------------------------------
    # Utility Methods
    # -------------------------------
    def _load_config(self, config_path):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def _load_yaml(self, tool_name, command_name):
        yaml_path = os.path.join(self.yaml_dir, tool_name, f"{command_name}.yaml")
        if not os.path.exists(yaml_path):
            raise FileNotFoundError(f"YAML manifest missing: {yaml_path}")
        loader = ManifestLoader(self.yaml_dir)
        return loader.load_manifest(tool_name, command_name)

    # -------------------------------
    # Core Execution Flow
    # -------------------------------
    def run_tool(self, tool_name, command_name):
        """
        Main driver to run any supported tool (e.g. nmap, ncat, sqlmap, etc.)
        Supports both simple flag-based manifests and services-based manifests (via adapters).
        """
        try:
            # 1️. Load YAML manifest
            manifest = self._load_yaml(tool_name, command_name)
            self.logger.info(f"Loaded manifest for {tool_name}/{command_name}")

            # Check if this is a services-based manifest (new format)
            if "services" in manifest:
                # Use adapter if available
                adapter_path = os.path.join("tools", tool_name, f"{command_name}_adapter.py")
                if os.path.exists(adapter_path):
                    self._run_with_adapter(tool_name, command_name, manifest)
                    return
                else:
                    print(f"\n[ERROR] Services-based manifest detected but no adapter found at: {adapter_path}")
                    print("[ERROR] Please create an adapter for this tool or use a flag-based manifest.")
                    return

            # 2️. Start interaction with user (for simple flag-based manifests)
            interaction = Interaction()
            user_inputs = interaction.collect_user_inputs(manifest)

            # 3️. Validate inputs
            valid_inputs = self._validate_inputs(user_inputs)

            # 4️. Build command
            # Handle both old format (command) and new format (command_id)
            base_command = manifest.get("command") or manifest.get("command_id", command_name)
            builder = CommandBuilder(base_command, valid_inputs)
            command = builder.build()
            print(f"\nGenerated Command:\n$ {command}")

            # 5️. Ask confirmation before execution
            confirm = input("\nDo you want to execute this command? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Command execution cancelled by user.")
                self.logger.info(f"User cancelled command: {command}")
                return

            # 6️. Execute the command
            print("\n[+] Running command...\n")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            # 7️. Log and save output
            if result.returncode == 0:
                self.logger.info(f"Command executed successfully: {command}")
                # Create reports directory structure
                reports_dir = self.config.get("reports_dir", "reports")
                tool_reports_dir = os.path.join(reports_dir, tool_name.lower())
                os.makedirs(tool_reports_dir, exist_ok=True)
                output_path = os.path.join(tool_reports_dir, f"{command_name}_output.txt")
                with open(output_path, "w") as f:
                    f.write(result.stdout)
                print(f"\n[+] Output saved to: {output_path}")
            else:
                self.logger.error(f"Command failed: {result.stderr}")
                print(f"\n Error executing command:\n{result.stderr}")

        except Exception as e:
            self.logger.error(f"Engine error: {str(e)}")
            print(f"\n[ERROR] {str(e)}")

    def _run_with_adapter(self, tool_name, command_name, manifest):
        """
        Run tool using an adapter for services-based manifests.
        """
        try:
            # Import and instantiate the adapter
            adapter_module_name = f"tools.{tool_name}.{command_name}_adapter"
            # Try common adapter class name patterns
            possible_class_names = [
                f"{command_name.title().replace('_', '')}Adapter",  # NcatAdapter
                f"{command_name.capitalize()}Adapter",  # NcatAdapter (alternative)
                f"{tool_name}{command_name.title().replace('_', '')}Adapter",  # NmapNcatAdapter
            ]

            # Try to import the adapter
            import importlib
            module = importlib.import_module(adapter_module_name)

            # Find the adapter class
            adapter_class = None
            for class_name in possible_class_names:
                if hasattr(module, class_name):
                    adapter_class = getattr(module, class_name)
                    break

            if adapter_class is not None:
                adapter = adapter_class(base_yaml_dir=self.yaml_dir)
                # Run the adapter's main method
                if hasattr(adapter, 'run'):
                    adapter.run()
                    return
                if hasattr(adapter, 'execute'):
                    adapter.execute()
                    return
                if hasattr(adapter, 'build_command'):
                    # Build command and execute it
                    result = adapter.build_command()
                    command = result.get("cmd_quoted", " ".join(result.get("cmd_list", [])))
                    print(f"\nGenerated Command:\n$ {command}")
                    confirm = input("\nDo you want to execute this command? (y/n): ").strip().lower()
                    if confirm != 'y':
                        print("Command execution cancelled by user.")
                        return
                    print("\n[+] Running command...\n")
                    exec_result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if exec_result.returncode == 0:
                        self.logger.info(f"Command executed successfully: {command}")
                        reports_dir = self.config.get("reports_dir", "reports")
                        tool_reports_dir = os.path.join(reports_dir, tool_name.lower())
                        os.makedirs(tool_reports_dir, exist_ok=True)
                        output_path = os.path.join(tool_reports_dir, f"{command_name}_output.txt")
                        with open(output_path, "w") as f:
                            f.write(exec_result.stdout)
                        print(f"\n[+] Output saved to: {output_path}")
                        if exec_result.stdout:
                            print(exec_result.stdout)
                    else:
                        self.logger.error(f"Command failed: {exec_result.stderr}")
                        print(f"\n[ERROR] Command failed:\n{exec_result.stderr}")
                    return

            # No adapter class found — try module-level functions
            for func_name in ('run', 'execute', 'build_command'):
                if hasattr(module, func_name):
                    func = getattr(module, func_name)
                    if func_name == 'build_command':
                        result = func()
                        command = result.get("cmd_quoted", " ".join(result.get("cmd_list", [])))
                        print(f"\nGenerated Command:\n$ {command}")
                        confirm = input("\nDo you want to execute this command? (y/n): ").strip().lower()
                        if confirm != 'y':
                            print("Command execution cancelled by user.")
                            return
                        print("\n[+] Running command...\n")
                        exec_result = subprocess.run(command, shell=True, capture_output=True, text=True)
                        if exec_result.returncode == 0:
                            self.logger.info(f"Command executed successfully: {command}")
                            reports_dir = self.config.get("reports_dir", "reports")
                            tool_reports_dir = os.path.join(reports_dir, tool_name.lower())
                            os.makedirs(tool_reports_dir, exist_ok=True)
                            output_path = os.path.join(tool_reports_dir, f"{command_name}_output.txt")
                            with open(output_path, "w") as f:
                                f.write(exec_result.stdout)
                            print(f"\n[+] Output saved to: {output_path}")
                            if exec_result.stdout:
                                print(exec_result.stdout)
                        else:
                            self.logger.error(f"Command failed: {exec_result.stderr}")
                            print(f"\n[ERROR] Command failed:\n{exec_result.stderr}")
                        return
                    else:
                        # run/execute expected to handle its own I/O
                        func()
                        return

            print(f"[ERROR] No adapter class or functions ('run', 'execute', 'build_command') found in {adapter_module_name}.")
            print(f"[ERROR] Please implement an adapter at tools/{tool_name}/{command_name}_adapter.py")
        except ImportError as e:
            print(f"[ERROR] Failed to import adapter: {e}")
            print(f"[ERROR] Make sure the adapter exists at tools/{tool_name}/{command_name}_adapter.py")
        except Exception as e:
            self.logger.error(f"Adapter error: {str(e)}")
            print(f"\n[ERROR] Adapter execution failed: {str(e)}")

    # -------------------------------
    # Validation Layer
    # -------------------------------
    def _validate_inputs(self, user_inputs):
        """
        Run multiple validators for correctness before building final command.
        Note: Basic validation is already done in UserInteraction class.
        This is a pass-through for now, but can be extended for additional validation.
        """
        validated = {}
        for key, value in user_inputs.items():
            # Basic validation - most validation happens in UserInteraction
            if isinstance(value, (str, int, float, bool)):
                validated[key] = value
            else:
                raise ValueError(f"Invalid input type for flag '{key}': {type(value)}")
        return validated


# --------------------------------
# Standalone Run Mode
# --------------------------------
if __name__ == "__main__":
    print("=== KaliTool AutoBot Engine ===")
    print("This is a backend engine module, not the main CLI entry point.")
    print("Use kalitool_autobot.py to start full workflow.\n")

    engine = Engine()
    tool = input("Enter tool name (e.g., Nmap, Sqlmap): ").strip()
    cmd = input("Enter command (e.g., ncat, nmap, sqlmap): ").strip()
    engine.run_tool(tool, cmd)
