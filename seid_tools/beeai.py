"""BeeAI model construction shared by Seid and Vardlokk."""

import importlib.metadata
import sys
from typing import Any

from beeai_framework.adapters.openai import OpenAIChatModel
from beeai_framework.backend import ChatModelParameters

from .config import get_app_config


def _prepare_beeai_compatibility() -> None:
    """Resolve BeeAI 0.1.79's deferred ChatModelKwargs under Python 3.14.

    BeeAI 0.1.80+ currently excludes Python 3.14. Version 0.1.79 declares
    support, but its Pydantic adapter may be initialized before resolving
    forward references on 3.14. Keep this workaround isolated for later removal.
    """
    if sys.version_info < (3, 14):
        return
    if importlib.metadata.version("beeai-framework") != "0.1.79":
        return

    from beeai_framework.backend import chat as chat_backend

    adapter = getattr(chat_backend, "_ChatModelKwargsAdapter", None)
    if adapter is not None:
        adapter.rebuild(force=True, _types_namespace=vars(chat_backend))


def get_beeai_model(
    app_name: str,
    model_id: str | None = None,
    *,
    temperature: float = 0.0,
) -> OpenAIChatModel:
    """Construct a BeeAI model from the existing per-application config."""
    _prepare_beeai_compatibility()
    config: dict[str, Any] = get_app_config(app_name)
    configured_model = model_id or config.get("model_id")
    api_base = config.get("model_api_base")
    api_key = config.get("model_api_key")
    if not configured_model or not api_base or not api_key:
        raise ValueError(f"{app_name} requires model_id, model_api_base, and model_api_key in seid.conf.")

    return OpenAIChatModel(
        model_id=configured_model,
        base_url=api_base,
        api_key=api_key,
        parameters=ChatModelParameters(temperature=temperature),
        allow_parallel_tool_calls=False,
        settings={
            "timeout": 600,
            # BeeAI owns tool discovery/execution; don't invoke LiteLLM's
            # optional proxy-MCP bridge for ordinary chat-completion tools.
            "_skip_mcp_handler": True,
        },
    )

