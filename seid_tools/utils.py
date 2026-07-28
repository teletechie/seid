"""
seid_tools.utils: Helper Utilities

Provides shared utility functions for the Seid ecosystem, primarily 
focusing on conversation history management. Managing history correctly 
is crucial to prevent the LLM's context window from overflowing over time.
"""

import json
import os
from typing import Dict, List

from .config import get_app_config


def get_history_file(app_name: str = "seid") -> str:
    """Resolves the absolute path to the history file for a given application."""
    cfg = get_app_config(app_name)
    # Expand '~' to the user's home directory in case it was set in the JSON config
    return os.path.expanduser(cfg.get("history_file", "~/.seid_history.json"))


def load_history(app_name: str = "seid", max_items: int = 4) -> List[Dict[str, str]]:
    """Loads recent conversation history to provide conversational context.
    
    Args:
        app_name: The application requesting the history ('seid' or 'vardlokk').
        max_items: The maximum number of past turns to load. Keeping this low 
                   is essential to prevent prompt bloat and context window limits.
    """
    history_file = get_history_file(app_name)
    
    if not os.path.exists(history_file):
        return []
        
    try:
        with open(history_file, 'r', encoding='utf-8') as f:
            history = json.load(f)
            # Slice the list to only return the most recent `max_items`
            return history[-max_items:]
    except json.JSONDecodeError:
        print(f"⚠ Warning: History file {history_file} is corrupted. Starting fresh.")
        return []
    except Exception as e:
        print(f"⚠ Warning: Could not read history file: {e}")
        return []


def save_history(user_query: str, agent_response: str, app_name: str = "seid"):
    """Saves a single interaction to the history file on disk.
    
    To prevent the JSON file from growing indefinitely, it loads a capped 
    number of historical items before appending the new one and saving.
    """
    history_file = get_history_file(app_name)
    
    # Load up to 10 previous items (we keep a slightly larger buffer on disk 
    # than what we inject into the prompt via max_items)
    history = load_history(app_name, max_items=10)
    
    # Append the new interaction
    history.append({
        "user": user_query, 
        "seid": agent_response
    })
    
    try:
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"⚠ Warning: Could not save history - {e}")