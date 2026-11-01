"""
seid_tools.config: Hierarchical Configuration Management

This module handles loading and merging configuration files for the Seid ecosystem.
It supports a fallback hierarchy:
1. Built-in defaults
2. System-wide configuration (/etc/seid/seid.conf)
3. User-specific overrides (~/.config/seid/seid.conf)

It also merges 'common' settings with application-specific settings (e.g., 'seid' or 'vardlokk').
"""

import copy
import json
import os
from typing import Any, Dict, Optional, Type

from smolagents import OpenAIServerModel

SYS_CONFIG_PATH = "/etc/seid/seid.conf"
USER_CONFIG_PATH = os.path.expanduser("~/.config/seid/seid.conf")

DEFAULT_CONFIG = {
    "common": {
        "model_api_base": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model_api_key": "set_in_config_file",
        "model_id": "gemini-2.5-flash",
        "command_timeout": 60
    },
    "seid": {
        "history_file": os.path.expanduser("~/.seid_history.json"),
        "max_piped_chars": 20000
    },
    "vardlokk": {
        "volve_api_url": "",
        "volve_agent_token": "",
        "volve_verify_ssl": True,  # Secure by default, matches vardlokk.py logic
        "history_file": os.path.expanduser("~/.vardlokk_history.json")
    }
}

def load_raw_config() -> Dict[str, Any]:
    """
    Loads the config files from disk and performs a section-level merge.
    User configurations safely override system configurations.
    """
    config = copy.deepcopy(DEFAULT_CONFIG)
    
    for path in [SYS_CONFIG_PATH, USER_CONFIG_PATH]:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    
                    # Merge sections (common, seid, vardlokk) independently
                    for section, values in file_config.items():
                        if section not in config:
                            config[section] = {}
                        if isinstance(values, dict):
                            config[section].update(values)
                            
            except json.JSONDecodeError as e:
                print(f"⚠ Warning: Malformed JSON in {path}: {e}")
            except Exception as e:
                print(f"⚠ Warning: Could not load config from {path}: {e}")
                
    return config

# Load configuration once at module initialization to avoid redundant disk I/O
_raw_config = load_raw_config()

def get_app_config(app_name: str) -> Dict[str, Any]:
    """
    Returns a merged configuration dictionary for a specific application.
    App-specific settings strictly override 'common' settings.
    """
    merged = _raw_config.get("common", {}).copy()
    merged.update(_raw_config.get(app_name, {}))
    return merged

def get_model(
    app_name: str,
    model_id: Optional[str] = None,
    model_class: Type[OpenAIServerModel] = OpenAIServerModel,
) -> Optional[OpenAIServerModel]:
    """
    Fetches a configured model instance based on the application's merged config.

    model_id optionally overrides the configured model, which lets callers try a
    different model without editing the configuration file. model_class lets a
    caller supply a subclass that adjusts how the provider's responses are
    interpreted.
    """
    cfg = get_app_config(app_name)
    try:
        return model_class(
            model_id=model_id or cfg.get("model_id"),
            api_base=cfg.get("model_api_base"),
            api_key=cfg.get("model_api_key"),
            # Extended timeout is necessary for large context queries, log parsing,
            # or slower on-premise models running on local hardware.
            timeout=600
        )
    except Exception as e:
        print(f"❌ Error: Could not initialize model for {app_name}: {e}")
        return None
        
