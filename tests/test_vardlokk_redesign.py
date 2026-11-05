"""Unit tests for Vardlokk's BeeAI tool boundary and report validation."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from seid_tools import linux_diagnostics
from vardlokk import parse_args
from vardlokk_agent import AuditFinding, AuditReport, Remediation, materialize_report


async def _run_tool(tool: object, arguments: dict[str, object]) -> object:
    return await tool.run(arguments)


def test_diagnostic_runner_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        observed["argv"] = argv
        observed.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="read-only output", stderr="")

    monkeypatch.setattr(linux_diagnostics.subprocess, "run", fake_run)
    result = linux_diagnostics._run_diagnostic(["df", "-h"])

    assert result["stdout"] == "read-only output"
    assert observed["shell"] is False
    assert observed["timeout"] == linux_diagnostics.COMMAND_TIMEOUT


def test_snapshot_returns_observed_linux_data() -> None:
    output = asyncio.run(_run_tool(linux_diagnostics.collect_host_snapshot, {}))
    data = json.loads(output.get_text_content())

    assert data["hostname"]
    assert data["memory_bytes"]["total"] > 0
    assert "filesystems" in data
    assert "swap_used_percent" in data["memory_bytes"]


def test_directory_scan_schema_is_limited_to_known_paths() -> None:
    schema = linux_diagnostics.inspect_directory_usage.input_schema.model_json_schema()
    assert schema["properties"]["path"]["enum"] == list(linux_diagnostics.DIRECTORY_SCAN_PATHS)


def test_systemd_unit_name_rejects_option_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        linux_diagnostics,
        "_run_diagnostic",
        lambda _argv: pytest.fail("invalid unit must be rejected before launching a process"),
    )
    result = asyncio.run(
        _run_tool(linux_diagnostics.inspect_systemd_unit, {"unit": "--no-pager;touch /tmp/pwned"})
    )
    assert "Invalid systemd unit name" in result.get_text_content()


def test_report_evidence_must_be_returned_by_a_tool() -> None:
    report = AuditReport(
        findings=[
            AuditFinding(
                finding_id="ROOT-FS",
                severity="high",
                category="storage",
                title="Root filesystem is full",
                description="The root filesystem has limited free space.",
                evidence_ids=["root123"],
                remediation=Remediation(
                    commands=["du -x -h --max-depth=1 -- /var"],
                    requires_reboot=False,
                    risk_of_breakage="low",
                ),
            )
        ]
    )
    tool_step = SimpleNamespace(
        tool=SimpleNamespace(name="collect_host_snapshot"),
        output=json.dumps(
            {
                "evidence": [
                    {"id": "abc123", "kind": "filesystem", "content": "/dev/example 95% /"},
                    {"id": "root123", "kind": "directory_usage", "content": "10G /var\n20G /"},
                ]
            }
        ),
    )
    audit_data = materialize_report(report, [tool_step])
    assert audit_data["findings"][0]["local_evidence"] == "/dev/example 95% /\n10G /var\n20G /"

    report.findings[0].evidence_ids = ["made-up"]
    with pytest.raises(ValueError, match="unknown evidence IDs"):
        materialize_report(report, [tool_step])

    report.findings[0].evidence_ids = ["root123"]
    report.findings[0].remediation.commands = ["rm -rf /var/lib/*"]
    sanitized = materialize_report(report, [tool_step])["findings"][0]
    assert sanitized["remediation"]["commands"] == []
    assert sanitized["remediation"]["risk_of_breakage"] == "high"
    assert "administrator review is required" in sanitized["description"]


def test_vardlokk_rejects_unsafe_override() -> None:
    with pytest.raises(SystemExit) as error:
        parse_args(["--unsafe"])
    assert error.value.code == 2


def test_investigate_scope_requires_alert_context() -> None:
    with pytest.raises(SystemExit) as error:
        parse_args(["--scope", "investigate"])
    assert error.value.code == 2

