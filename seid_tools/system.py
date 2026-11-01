"""
seid_tools.system: System Interaction Tools and Sandboxing

Provides the core tools allowing the LLM to interact with the host OS.
Critically, it wraps potentially dangerous commands in `systemd-run` 
transient scopes to enforce read-only namespaces at the kernel level, 
protecting the host system from LLM hallucinations or prompt injection.
"""

import os
import shlex
import subprocess
import sys
from typing import Optional

from smolagents import tool

# Global state controlled by the main applications (Seid or Vardlokk)
ALLOW_UNSAFE_ACTIONS = False
INTERACTIVE_MODE = True

# Max output sizes to protect the LLM context window limits
MAX_CMD_OUTPUT = 8000
MAX_FILE_OUTPUT = 6000

# How long a single command may run before it is abandoned. Audit and
# troubleshooting commands such as 'du', 'journalctl' or 'ps' routinely need
# longer than a few seconds, so this is configurable from seid.conf.
COMMAND_TIMEOUT = 60

# We rely on systemd-run (ProtectSystem=full) to prevent filesystem mutations (rm, dd, etc.).
# --user is essential: without it systemd-run targets the SYSTEM manager, which
# asks polkit/GNOME for an admin password and runs the command as root.
# However, systemd-run does NOT block IPC/Socket communications. 
# Therefore, we explicitly block keywords that can mutate system state via sockets 
# (like dbus or the docker daemon) when running in strict read-only mode.
UNSAFE_IPC_KEYWORDS = [
    'rm ', 'chmod ', 'chown ', 'mkfs', 'dd ',
    'systemctl start', 'systemctl stop', 'systemctl restart', 
    'systemctl disable', 'systemctl enable', 'reboot', 'shutdown',
    'podman run', 'podman pod create', 'podman rm', 'podman stop',
    'docker run', 'docker rm', 'docker stop', 'compose up', 'compose down'
]

def set_unsafe_mode(mode: bool):
    """Toggles whether the agent is allowed to execute state-mutating commands."""
    global ALLOW_UNSAFE_ACTIONS
    ALLOW_UNSAFE_ACTIONS = mode

def set_interactive_mode(mode: bool):
    """Toggles human-in-the-loop prompts for command execution."""
    global INTERACTIVE_MODE
    INTERACTIVE_MODE = mode

def set_command_timeout(seconds: int):
    """Sets how long a single command may run before it is abandoned.

    Invalid values are ignored with a warning so a typo in the configuration
    cannot leave the agent with a zero or negative timeout.
    """
    global COMMAND_TIMEOUT
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        print(f"⚠ Warning: invalid command_timeout {seconds!r}; keeping {COMMAND_TIMEOUT}s.")
        return
    if value < 1:
        print(f"⚠ Warning: command_timeout must be at least 1 second; keeping {COMMAND_TIMEOUT}s.")
        return
    COMMAND_TIMEOUT = value


def _request_approval(command: str) -> tuple[Optional[bool], str]:
    """Asks the human to approve a command on the controlling terminal.

    Returns (decision, reason). decision is True or False for an answer, or
    None when no terminal is available; reason then explains why. Reading from
    /dev/tty rather than stdin keeps approval working when the user pipes data
    into Seid (stdin is already at EOF in that case).
    """
    prompt = f"Allow '{command}'? (y/N): "
    answer: Optional[str] = None
    reason = ""

    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            answer = tty.readline()
            if not answer:
                answer = None
                reason = "/dev/tty closed before an answer"
    except (OSError, EOFError) as e:
        reason = f"/dev/tty: {e}"

    # Fall back to stdin only when it is a real terminal. Some containers and
    # remote sessions expose stdin but not /dev/tty.
    if answer is None and sys.stdin.isatty():
        try:
            answer = input(prompt)
            reason = ""
        except (EOFError, OSError) as e:
            reason = f"stdin: {e}"

    if answer is None:
        return None, reason or "stdin is not a terminal"

    return answer.strip().lower() == "y", ""


@tool
def run_local_command(command: str) -> str:
    """Runs a CLI command locally on the system to inspect state, network, logs, or hardware.
    
    Args:
        command: The bash command to run (e.g., 'ip a', 'journalctl -n 20', 'systemctl status').
    """
    if not ALLOW_UNSAFE_ACTIONS:
        # 1. Block IPC/Socket mutations that bypass filesystem protections
        if any(keyword in command for keyword in UNSAFE_IPC_KEYWORDS):
            return f"SYSTEM BLOCK: '{command}' contains blocked IPC/socket keywords. Use --unsafe to allow."
        
        # 2. Wrap the command in a systemd-run sandbox to protect the filesystem
        # shlex.quote ensures special characters cannot break out of the bash -c string
        safe_command = (
            "systemd-run --user --pipe --wait --quiet "
            "-p ProtectSystem=full "
            "-p ProtectHome=read-only "
            "-p ProtectControlGroups=yes "
            "-p ProtectKernelTunables=yes "
            "-p NoNewPrivileges=yes "
            f"-- bash -c {shlex.quote(command)}"
        )
    else:
        # Unsafe mode: The agent is allowed to run the raw command unconstrained
        safe_command = f"bash -c {shlex.quote(command)}"

    print(f"\n[EXECUTE]: {command}", flush=True)

    if INTERACTIVE_MODE:
        approval, reason = _request_approval(command)
        if approval is None:
            return (
                "SYSTEM BLOCK: Command not run because no terminal is available for approval "
                f"({reason}). Re-run Seid from an interactive terminal to approve it."
            )
        if not approval:
            return "User aborted the command for security reasons."
    else:
        print("[AUTO-APPROVED: Running in headless mode]")
        
    try:
        # We execute the sandboxed command, never the raw LLM output
        result = subprocess.run(safe_command, shell=True, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        output = result.stdout if result.stdout else result.stderr
        
        if len(output) > MAX_CMD_OUTPUT:
            return output[:MAX_CMD_OUTPUT] + "\n\n... [OUTPUT TRUNCATED TO SAVE CONTEXT WINDOW]"
            
        return output.strip() if output else "Command ran without output."
        
    except subprocess.TimeoutExpired:
        return f"Command failed: Timeout ({COMMAND_TIMEOUT}s)."
    except Exception as e:
        return f"Command failed: {str(e)}"


@tool
def read_system_file(filepath: str) -> str:
    """Reads the contents of local text files to gather configuration, logs, or system state.
    
    Args:
        filepath: The absolute or relative path to the file (e.g., '/etc/fstab', '~/.bashrc', '/proc/meminfo').
    """
    real_path = os.path.realpath(os.path.expanduser(filepath))
    
    if not os.path.exists(real_path):
        return f"Error: The file {filepath} does not exist."
        
    if not os.path.isfile(real_path):
        return f"Error: {filepath} is not a regular file (it might be a directory)."
        
    try:
        with open(real_path, 'r', encoding='utf-8') as f:
            # Read slightly more than the max so we know if we need to append the truncation warning
            content = f.read(MAX_FILE_OUTPUT + 1) 
            
        if len(content) > MAX_FILE_OUTPUT:
            return content[:MAX_FILE_OUTPUT] + "\n\n... [FILE TRUNCATED DUE TO LENGTH]"
            
        return content.strip() if content else "File exists but is empty."
        
    except UnicodeDecodeError:
        return f"Error: {filepath} appears to be a binary file. Can only read text files."
    except PermissionError:
        return f"Error: Permission denied. No read access to {filepath}."
    except Exception as e:
        return f"Error reading file: {str(e)}"


@tool
def find_system_file(filename: str, search_dir: str = "/etc") -> str:
    """Finds the absolute paths of files on the system using the 'find' command.
    
    Args:
        filename: The exact name or pattern of the file to find (e.g., 'nginx.conf', '*.log', 'kubeconfig').
        search_dir: The directory to start searching in to save time. Defaults to '/etc'. Examples: '/var/log', '~', '/'.
    """
    real_dir = os.path.expanduser(search_dir)
    
    if not os.path.isdir(real_dir):
        return f"Error: The directory '{search_dir}' does not exist."
        
    # SECURITY FIX: shlex.quote prevents the agent from injecting commands into the filename or search_dir arguments
    cmd = f"find {shlex.quote(real_dir)} -type f -name {shlex.quote(filename)} 2>/dev/null | head -n 20"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        
        output = result.stdout.strip()
        if not output:
            return f"No files matching '{filename}' were found in '{search_dir}'."
            
        return f"Found the following files:\n{output}"
        
    except subprocess.TimeoutExpired:
        return f"Search timed out after {COMMAND_TIMEOUT} seconds."
    except Exception as e:
        return f"Command failed: {str(e)}"
