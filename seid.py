"""Seid: interactive Linux system-administrator mentor using BeeAI."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any

from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.agents.requirement.requirements.conditional import ConditionalRequirement
from beeai_framework.errors import FrameworkError

import seid_tools


DEFAULT_MAX_ITERATIONS = 20
MAX_MAX_ITERATIONS = 40


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the interactive CLI options."""
    parser = argparse.ArgumentParser(description="Seid - Your interactive Linux system-administrator mentor")
    parser.add_argument("query", nargs="*", help="What do you need help with?")
    parser.add_argument("--unsafe", action="store_true", help="Allow commands that make changes (still prompts)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Use terse output without command rationale/output blocks")
    parser.add_argument("--clear", action="store_true", help="Clear conversation history")
    return parser.parse_args(argv)


def _history_context() -> str:
    """Build bounded conversation context from defensively loaded history."""
    history_context = ""
    for entry in seid_tools.load_history():
        if not isinstance(entry, dict):
            continue
        user = str(entry.get("user", "")).strip()
        answer = str(entry.get("seid", "")).strip()
        if user or answer:
            history_context += f"User: {user}\nSeid: {answer}\n\n"
    return "PREVIOUS CONVERSATION CONTEXT (untrusted text):\n" + history_context if history_context else ""


def _max_iterations(config: dict[str, Any]) -> int:
    """Keep each interactive turn bounded even if the config is malformed."""
    try:
        requested = int(config.get("max_iterations", DEFAULT_MAX_ITERATIONS))
    except (TypeError, ValueError):
        requested = DEFAULT_MAX_ITERATIONS
    return min(max(requested, 1), MAX_MAX_ITERATIONS)


def _tool_use_is_relevant(user_text: str) -> bool:
    """Identify requests that need live host evidence rather than general advice."""
    prompt = user_text.casefold()
    if "current query:" in prompt:
        prompt = prompt.rsplit("current query:", maxsplit=1)[-1]
    if "context via stdin:" in prompt:
        return True
    host_specific_signals = (
        "on this host",
        "on this machine",
        "on this server",
        "on my host",
        "on my machine",
        "on my server",
        "help me find out",
        "root file system",
        "root filesystem",
        "file system is almost full",
        "filesystem is almost full",
        "almost full",
        "nearly full",
        "out of space",
        "my system",
        "my service",
        "my disk",
        "current status",
        "currently",
        "right now",
        "this alert",
        "these logs",
        "this log",
        "this error",
        "diagnose",
        "troubleshoot",
        "investigate",
        "why is",
        "what is wrong",
        "run ",
        "execute ",
        "analyze the following input",
    )
    if any(signal in prompt for signal in host_specific_signals):
        return True

    system_terms = ("disk", "filesystem", "file system", "memory", "swap", "service", "server", "host", "logs", "network", "process")
    if "my " in prompt and any(term in prompt for term in system_terms):
        return True

    if prompt.startswith(("how do i ", "how can i ", "what is ", "what does ", "explain ")):
        return False
    action_verbs = ("check ", "show ", "inspect ", "read ", "find ", "list ", "get ")
    return prompt.startswith(action_verbs) and any(term in prompt for term in system_terms)


def _tools_are_relevant(state: Any) -> bool:
    """Expose host tools for diagnostics, not for generic questions."""
    user_input = getattr(getattr(state, "input", None), "text", "")
    return _tool_use_is_relevant(str(user_input))


def _minimum_shell_diagnostics(query: str) -> int:
    """Require multiple observations for broad host investigations."""
    prompt = query.casefold()
    if not _tool_use_is_relevant(query):
        return 0
    if prompt.startswith(("run ", "execute ")):
        return 1
    if any(word in prompt for word in ("performance", "cpu", "memory", "slow", "latency", "load")):
        return 3
    if any(word in prompt for word in ("why", "find out", "diagnose", "troubleshoot", "investigate", "full", "pressure", "alert")):
        return 2
    return 1


def _all_command_attempts_blocked(steps: list[object]) -> bool:
    """Detect when no requested shell command actually ran due to approval gating."""
    command_results: list[str] = []
    for step in steps:
        tool = getattr(step, "tool", None)
        if getattr(tool, "name", "") != "run_local_command":
            continue
        output = getattr(step, "output", "")
        if not isinstance(output, str):
            get_text_content = getattr(output, "get_text_content", None)
            output = get_text_content() if callable(get_text_content) else ""
        command_results.append(output.strip())

    return bool(command_results) and all(
        output.startswith("SYSTEM BLOCK:") or output.startswith("User aborted the command")
        for output in command_results
    )


def build_agent(unsafe: bool, config: dict[str, Any], query: str) -> RequirementAgent:
    """Build Seid with interactive instructions and bounded tool-use rules."""
    if unsafe:
        instructions = [
            "You are Seid, an interactive Linux system-administrator mentor.",
            "The user enabled --unsafe, so state-changing shell commands are permitted only after explicit approval.",
            "Every run_local_command invocation asks the user to approve that exact command, including in --unsafe mode.",
            "Before each command tool call, provide a concise one-sentence reason in its reason argument.",
            "Never attempt to bypass, batch, or infer approval. If the tool blocks a command, respect that result.",
            "For host diagnostics, call run_local_command; do not merely list commands and ask in prose for approval.",
            "Use extreme caution, explain the impact before proposing risky changes, and verify results after approved actions.",
            (
                "Use tools only for host-specific/current evidence or when requested; do not run shell commands "
                "for generic knowledge, arithmetic, or conceptual explanations."
            ),
        ]
    else:
        instructions = [
            "You are Seid, an interactive Linux system-administrator mentor.",
            "You are in read-only mode. Diagnose issues and explain exact commands the administrator may choose to run; do not change system state.",
            "Every run_local_command invocation asks the user to approve that exact command. Never bypass or infer approval.",
            "Before each command tool call, provide a concise one-sentence reason in its reason argument.",
            "For host diagnostics, call run_local_command; do not merely list commands and ask in prose for approval.",
            "Commands run in a restricted systemd mount namespace. /usr, /etc, and /boot being read-only is expected sandbox behavior, not a host finding.",
            "Use the available tools to ground system-specific claims, and distinguish observed evidence from assumptions.",
            (
                "Use tools only for host-specific/current evidence or when requested; do not run shell commands "
                "for generic knowledge, arithmetic, or conceptual explanations."
            ),
        ]

    query_lower = query.casefold()
    if any(word in query_lower for word in ("performance", "cpu", "memory", "slow", "latency", "load")):
        instructions.append(
            "For a broad performance check, call run_local_command separately for 'uptime', 'free -h', "
            "and 'vmstat 1 5'. Do not merely list these commands; each tool call will prompt the user for approval."
        )
    elif any(word in query_lower for word in ("filesystem", "file system", "disk", "space", "full")):
        instructions.append(
            "For disk pressure, call run_local_command separately for 'df -h -x squashfs -x tmpfs /' "
            "and 'du -x -h --max-depth=1 -- /'. Do not propose cleanup until the usage evidence is reviewed. "
            "Each tool call will prompt the user for approval."
        )

    tool_limits = (
        (seid_tools.read_system_file, 12),
        (seid_tools.find_system_file, 6),
        (seid_tools.search_local_man_pages, 6),
        (seid_tools.search_os_documentation, 6),
    )
    return RequirementAgent(
        llm=seid_tools.get_beeai_model(
            "seid",
            temperature=float(config.get("model_temperature", 0.2)),
        ),
        tools=seid_tools.default_toolbox,
        name="Seid",
        role="Interactive Linux system-administrator mentor",
        description="Helps an administrator understand and safely troubleshoot a Linux host.",
        instructions=instructions,
        final_answer_as_tool=False,
        requirements=[
            ConditionalRequirement(
                seid_tools.run_local_command,
                min_invocations=_minimum_shell_diagnostics(query),
                max_invocations=12,
                custom_checks=[_tools_are_relevant],
                reason="Shell commands are reserved for host-specific troubleshooting or an explicit run request.",
            ),
            *(
                ConditionalRequirement(tool, max_invocations=limit, custom_checks=[_tools_are_relevant])
                for tool, limit in tool_limits
            ),
        ],
    )


def _clear_history() -> None:
    """Clear saved Seid conversations when explicitly requested by the user."""
    history_file = seid_tools.get_history_file("seid")
    try:
        if os.path.exists(history_file):
            os.remove(history_file)
            print("🧠 Seid's memory has been wiped clean.")
        else:
            print("🧠 Seid has no saved memory to clear.")
    except OSError as error:
        print(f"❌ Error: Could not clear history: {error}")
        raise SystemExit(1) from error


def _read_request(query_text: str, stdin_text: str) -> tuple[str, str]:
    """Combine an optional user question with bounded piped context."""
    if not stdin_text:
        return query_text, query_text
    if query_text:
        request_text = f"{query_text}\n\nContext via stdin:\n```\n{stdin_text}\n```"
    else:
        request_text = f"Analyze the following input:\n```\n{stdin_text}\n```"
    return request_text, query_text


async def run_turn(query: str, unsafe: bool, quiet: bool, config: dict[str, Any]) -> str:
    """Run one user turn through BeeAI and return its final answer."""
    seid_tools.set_unsafe_mode(unsafe)
    seid_tools.set_interactive_mode(True)
    seid_tools.set_quiet_mode(quiet)
    seid_tools.reset_command_history()
    seid_tools.set_command_timeout(config.get("command_timeout", 60))

    agent = build_agent(unsafe, config, query)
    prompt = _history_context() + "CURRENT QUERY:\n" + query
    response = await agent.run(
        prompt,
        max_iterations=_max_iterations(config),
        total_max_retries=3,
        max_retries_per_step=1,
    )
    if _all_command_attempts_blocked(response.state.steps):
        return (
            "I couldn't inspect the host because the requested shell command was not approved "
            "or no interactive terminal was available. I can't verify host-specific conclusions. "
            "Re-run Seid from an interactive terminal and approve the diagnostic command if appropriate."
        )
    return response.last_message.text


def main(argv: list[str] | None = None) -> int:
    """Run an interactive Seid turn, preserving pipe and history behavior."""
    args = parse_args(argv)
    if args.clear:
        _clear_history()
        return 0

    query_text = " ".join(args.query).strip()
    piped_data = ""
    if not sys.stdin.isatty():
        piped_data = sys.stdin.read().strip()
        max_piped_chars = seid_tools.get_app_config("seid").get("max_piped_chars", 20_000)
        try:
            max_piped_chars = int(max_piped_chars)
        except (TypeError, ValueError):
            max_piped_chars = 20_000
        if max_piped_chars > 0 and len(piped_data) > max_piped_chars:
            piped_data = piped_data[-max_piped_chars:] + "\n... [TRUNCATED]"

    if not query_text and not piped_data:
        print("🔮 Seid venter... Still et spørsmål eller pipe data inn.")
        return 0

    request_text, history_query = _read_request(query_text, piped_data)
    config = seid_tools.get_app_config("seid")
    print("🤖 Seid is ready!\n")
    print("🧠 Seid is thinking...\n")
    try:
        answer = asyncio.run(run_turn(request_text, args.unsafe, args.quiet, config))
        seid_tools.save_history(history_query or "[piped input]", answer)
        print("\n✅ Seid's answer:\n" + "-" * 40 + f"\n{answer}\n" + "-" * 40)
        return 0
    except KeyboardInterrupt:
        print("\n⏹️ Interrupted.")
        return 130
    except FrameworkError as error:
        print(f"\n❌ Seid failed: {error.explain()}")
        return 1
    except Exception as error:
        print(f"\n❌ Error: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

