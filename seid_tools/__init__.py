"""
seid_tools: The shared toolchain for the Seid ecosystem.

This package provides the core tools, system interaction wrappers, 
and configuration management used by both Seid (interactive CLI) 
and Vardlokk (automated auditor). 
"""

# Core system interaction and safety toggles
from .system import (
    find_system_file,
    read_system_file,
    run_local_command,
    set_interactive_mode,
    set_unsafe_mode,
)

# Documentation and knowledge retrieval tools
from .documentation import (
    search_local_man_pages,
    search_os_documentation,
)

# Configuration and state management
from .config import get_app_config, get_model
from .utils import load_history, save_history

# The default set of tools provided to the smolagents ToolCallingAgent.
# These functions must be decorated with @tool in their respective modules.
default_toolbox = [
    run_local_command,
    read_system_file,
    find_system_file,
    search_local_man_pages,
    search_os_documentation
]

# Explicitly define the public API of this package.
# This prevents unintended internal modules from being imported if 
# someone uses `from seid_tools import *`.
__all__ = [
    "default_toolbox",
    "find_system_file",
    "get_app_config",
    "get_model",
    "load_history",
    "read_system_file",
    "run_local_command",
    "save_history",
    "search_local_man_pages",
    "search_os_documentation",
    "set_interactive_mode",
    "set_unsafe_mode",
]