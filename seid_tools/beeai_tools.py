"""BeeAI adapters for Seid's existing Linux and documentation functions."""

import sys

from beeai_framework.tools import StringToolOutput, tool

from . import documentation, system

QUIET_MODE = False


def set_quiet_mode(enabled: bool) -> None:
    """Select terse output or mentor-style command explanations and results."""
    global QUIET_MODE
    QUIET_MODE = bool(enabled)


@tool
def run_local_command(command: str, reason: str) -> StringToolOutput:
    """Run one approved local shell command.

    Args:
        command: The exact shell command to run on the local Linux host.
        reason: One short sentence explaining why this command helps answer the user's request.

    Every call requires interactive human approval, including in --unsafe mode.
    """
    if not QUIET_MODE:
        short_reason = " ".join(reason.strip().split())[:300]
        if not short_reason:
            short_reason = "This command is needed to gather evidence for your request."
        print(f"\n🧭 Why Seid wants to run this: {short_reason}", flush=True)

    result = system.run_local_command(command)
    if not QUIET_MODE:
        if result.startswith("SYSTEM BLOCK:") or result.startswith("User aborted the command"):
            print(f"\n⚠ Command was not run: {result}", flush=True)
        else:
            print("\n📤 Command output:", flush=True)
            print(result, flush=True)
    return StringToolOutput(result=result)


@tool
def read_system_file(filepath: str) -> StringToolOutput:
    """Read a text file on the local Linux host."""
    return StringToolOutput(result=system.read_system_file(filepath))


@tool
def find_system_file(filename: str, search_dir: str = "/etc") -> StringToolOutput:
    """Find files by name in a local directory."""
    return StringToolOutput(result=system.find_system_file(filename, search_dir))


@tool
def search_local_man_pages(query: str) -> StringToolOutput:
    """Search local manual pages for command usage and flags."""
    return StringToolOutput(result=documentation.search_local_man_pages(query))


@tool
def search_os_documentation(query: str, os_name: str = "linux") -> StringToolOutput:
    """Search official operating-system documentation for a technical question."""
    return StringToolOutput(result=documentation.search_os_documentation(query, os_name))


default_toolbox = [
    run_local_command,
    read_system_file,
    find_system_file,
    search_local_man_pages,
    search_os_documentation,
]

