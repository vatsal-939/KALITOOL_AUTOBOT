#!/usr/bin/env python3
"""
KaliTool AutoBot — Unified CLI Tool for Security Command Automation
Description:
    This script is the MAIN ENTRY POINT of the KaliTool AutoBot system.
    It acts as a high-level interface, loading available tools, reading YAML manifests,
    and invoking the Engine to execute commands dynamically.
"""

import os
import sys
import yaml
from engine import Engine


# --------------------------------------
# Helper Functions
# --------------------------------------
def list_available_tools(yaml_dir):
    """
    List all available tools and their respective commands
    based on YAML manifests in yaml_dir.
    """
    tools = {}
    if not os.path.exists(yaml_dir):
        print(f"[ERROR] YAML directory not found: {yaml_dir}")
        return tools

    for tool in os.listdir(yaml_dir):
        tool_path = os.path.join(yaml_dir, tool)
        # Skip hidden directories and __pycache__
        if os.path.isdir(tool_path) and not tool.startswith('.') and tool != '__pycache__':
            commands = [f.replace(".yaml", "") for f in os.listdir(tool_path) if f.endswith(".yaml")]
            if commands:  # Only add if there are actual YAML files
                tools[tool] = commands
    return tools


def display_menu(tools):
    """
    Display available tools and commands interactively.
    """
    print("\n=== Available Tools ===")
    for idx, (tool, cmds) in enumerate(tools.items(), 1):
        print(f"{idx}. {tool} - {len(cmds)} commands")

    try:
        choice = int(input("\nSelect tool number: ").strip())
        if choice < 1 or choice > len(tools):
            raise ValueError
    except ValueError:
        print("[!] Invalid selection.")
        sys.exit(1)

    selected_tool = list(tools.keys())[choice - 1]
    return selected_tool


def display_commands(tool, tools_dict):
    """
    Display all available commands for selected tool.
    """
    print(f"\n=== {tool.upper()} Available Commands ===")
    commands = tools_dict.get(tool, [])
    for idx, cmd in enumerate(commands, 1):
        print(f"{idx}. {cmd}")

    try:
        cmd_choice = int(input("\nSelect command number: ").strip())
        if cmd_choice < 1 or cmd_choice > len(commands):
            raise ValueError
    except ValueError:
        print("[!] Invalid command selection.")
        sys.exit(1)

    return commands[cmd_choice - 1]


# --------------------------------------
# Main Function
# --------------------------------------
def main():
    print("""
 ╔════════════════════════════════════════════════════════════╗
║              🔥  KaliTool AutoBot v1.0 (CLI)  🔥            ║
║    Automate, Validate & Execute Kali Commands from YAML      ║
 ╚════════════════════════════════════════════════════════════╝
    """)

    config_path = "config.yaml"
    if not os.path.exists(config_path):
        print("[ERROR] config.yaml not found. Please create it first.")
        sys.exit(1)

    # Load config to find YAML directory
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        
    yaml_dir = config["yaml_dir"]

    # Step 1: List all tools and commands
    tools = list_available_tools(yaml_dir)
    if not tools:
        print("[ERROR] No tools found in YAML directory.")
        sys.exit(1)

    # Step 2: Select tool
    selected_tool = display_menu(tools)

    # Step 3: Select command
    selected_command = display_commands(selected_tool, tools)

    # Step 4: Initialize Engine and run
    engine = Engine(config_path)
    engine.run_tool(selected_tool, selected_command)


# --------------------------------------
# Entry Point
# --------------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting gracefully...")
        sys.exit(0)
