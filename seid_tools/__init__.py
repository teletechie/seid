"""Shared Seid and Vardlokk configuration and BeeAI tool APIs."""

from .beeai import get_beeai_model
from .beeai_tools import (
    default_toolbox,
    find_system_file,
    read_system_file,
    run_local_command,
    search_local_man_pages,
    search_os_documentation,
    set_quiet_mode,
)
from .config import get_app_config
from .system import reset_command_history, set_command_timeout, set_interactive_mode, set_unsafe_mode
from .utils import get_history_file, load_history, save_history

# Keep the old public factory name as an alias during the framework migration.
get_model = get_beeai_model

__all__ = [
    "default_toolbox",
    "find_system_file",
    "get_app_config",
    "get_beeai_model",
    "get_history_file",
    "get_model",
    "load_history",
    "read_system_file",
    "reset_command_history",
    "run_local_command",
    "save_history",
    "search_local_man_pages",
    "search_os_documentation",
    "set_command_timeout",
    "set_interactive_mode",
    "set_quiet_mode",
    "set_unsafe_mode",
]

