"""Tests for Seid's BeeAI adapters and approval invariant."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from seid import _all_command_attempts_blocked, _minimum_shell_diagnostics, _tools_are_relevant, parse_args
from seid_tools import beeai, beeai_tools
from seid_tools import system


def test_unsafe_mode_still_requires_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    system.reset_command_history()


def test_command_output_contains_stdout_stderr_and_exit_status(monkeypatch: pytest.MonkeyPatch) -> None:
    system.reset_command_history()
    system.set_unsafe_mode(True)
    system.set_interactive_mode(True)
    monkeypatch.setattr(system, "_request_approval", lambda _command: (True, ""))
    monkeypatch.setattr(
        system.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=2, stdout="stdout data", stderr="stderr data"),
    )
    try:
        output = system.run_local_command("example-command")
    finally:
        system.set_unsafe_mode(False)
        system.set_interactive_mode(True)
        system.reset_command_history()

    assert "stdout data" in output
    assert "[stderr]\nstderr data" in output
    assert "[Command exited with status 2]" in output
    approval_calls: list[str] = []

    def deny(command: str) -> tuple[bool, str]:
        approval_calls.append(command)
        return False, ""

    def must_not_run(*_args: object, **_kwargs: object) -> None:
        pytest.fail("command executed without human approval")

    monkeypatch.setattr(system, "_request_approval", deny)
    monkeypatch.setattr(system.subprocess, "run", must_not_run)
    system.set_unsafe_mode(True)
    system.set_interactive_mode(True)
    try:
        result = system.run_local_command("touch /tmp/seid-approval-test")
    finally:
        system.set_unsafe_mode(False)
        system.set_interactive_mode(True)

    assert approval_calls == ["touch /tmp/seid-approval-test"]
    assert result == "User aborted the command for security reasons."
    duplicate = system.run_local_command("touch /tmp/seid-approval-test")
    assert duplicate.startswith("SYSTEM BLOCK:")
    assert approval_calls == ["touch /tmp/seid-approval-test"]
    system.reset_command_history()


def test_beeai_command_tool_shows_reason_and_output_by_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(system, "run_local_command", lambda command: f"approved result: {command}")
    result = asyncio.run(
        _run_tool(
            beeai_tools.run_local_command,
            {"command": "df -h /", "reason": "Check current root filesystem capacity."},
        )
    )
    assert result.get_text_content() == "approved result: df -h /"
    output = capsys.readouterr().out
    assert "Check current root filesystem capacity." in output
    assert "approved result: df -h /" in output


async def _run_tool(tool: object, arguments: dict[str, object]) -> object:
    return await tool.run(arguments)


def test_beeai_toolbox_contains_only_the_expected_seid_tools() -> None:
    assert [tool.name for tool in beeai_tools.default_toolbox] == [
        "run_local_command",
        "read_system_file",
        "find_system_file",
        "search_local_man_pages",
        "search_os_documentation",
    ]


def test_model_serializes_tool_calls_and_skips_litellm_mcp_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        beeai,
        "get_app_config",
        lambda _app: {
            "model_id": "test-model",
            "model_api_base": "http://localhost:11434/v1",
            "model_api_key": "not_needed",
        },
    )
    model = beeai.get_beeai_model("seid", temperature=0.2)

    assert model.allow_parallel_tool_calls is False
    assert model._settings["_skip_mcp_handler"] is True
    assert model.parameters.temperature == 0.2


def test_quiet_flag_and_tool_mode_suppress_mentor_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert parse_args(["-q", "What is uptime?"]).quiet
    monkeypatch.setattr(system, "run_local_command", lambda command: f"result: {command}")
    beeai_tools.set_quiet_mode(True)
    try:
        result = asyncio.run(
            _run_tool(
                beeai_tools.run_local_command,
                {"command": "uptime", "reason": "Check current host load."},
            )
        )
    finally:
        beeai_tools.set_quiet_mode(False)
    assert result.get_text_content() == "result: uptime"
    assert capsys.readouterr().out == ""


def test_tools_are_reserved_for_host_specific_work() -> None:
    generic_question = SimpleNamespace(input=SimpleNamespace(text="What is 2 + 2?"))
    host_question = SimpleNamespace(input=SimpleNamespace(text="Why is my nginx service failing?"))
    root_pressure = SimpleNamespace(
        input=SimpleNamespace(text="help me find out why the root file system is almost full")
    )
    explicit_command = SimpleNamespace(input=SimpleNamespace(text="Run df -h /"))
    how_to_question = SimpleNamespace(input=SimpleNamespace(text="How do I check disk usage?"))
    piped_diagnostics = SimpleNamespace(input=SimpleNamespace(text="Analyze the following input: journalctl output"))
    old_diagnostic_history = SimpleNamespace(
        input=SimpleNamespace(text="PREVIOUS CONTEXT: why is my disk full? CURRENT QUERY: What is 2 + 2?")
    )

    assert not _tools_are_relevant(generic_question)
    assert _tools_are_relevant(host_question)
    assert _tools_are_relevant(root_pressure)
    assert _tools_are_relevant(explicit_command)
    assert not _tools_are_relevant(how_to_question)
    assert _tools_are_relevant(piped_diagnostics)
    assert not _tools_are_relevant(old_diagnostic_history)


def test_broad_host_checks_require_multiple_shell_observations() -> None:
    assert _minimum_shell_diagnostics("What is 2 + 2?") == 0
    assert _minimum_shell_diagnostics("Run df -h /") == 1
    assert _minimum_shell_diagnostics("Help me find out why the root file system is almost full") == 2
    assert _minimum_shell_diagnostics("Check for performance problems on this host") == 3


def test_seid_does_not_claim_results_when_approval_blocked() -> None:
    blocked = SimpleNamespace(
        tool=SimpleNamespace(name="run_local_command"),
        output="SYSTEM BLOCK: no terminal available for approval",
    )
    denied = SimpleNamespace(
        tool=SimpleNamespace(name="run_local_command"),
        output="User aborted the command for security reasons.",
    )
    executed = SimpleNamespace(
        tool=SimpleNamespace(name="run_local_command"),
        output="Filesystem /dev/sda1 is 80% used",
    )

    assert _all_command_attempts_blocked([blocked, denied])
    duplicate_block = SimpleNamespace(
        tool=SimpleNamespace(name="run_local_command"),
        output="SYSTEM BLOCK: This exact command was already attempted during this Seid turn.",
    )
    assert _all_command_attempts_blocked([blocked, duplicate_block])
    assert not _all_command_attempts_blocked([blocked, executed])
    assert not _all_command_attempts_blocked([])

