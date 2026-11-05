"""BeeAI-based Vardlokk investigation agent and report schema."""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field

from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.agents.requirement.requirements.conditional import ConditionalRequirement
from beeai_framework.backend import ChatModel

from seid_tools.linux_diagnostics import (
    VARDLOKK_DIAGNOSTIC_TOOLS,
    collect_host_snapshot,
    inspect_directory_usage,
    inspect_systemd_unit,
)


class Remediation(BaseModel):
    """Human-reviewed remediation guidance compatible with Volve's API."""

    action_type: Literal["cli_commands"] = "cli_commands"
    commands: list[str] = Field(max_length=8)
    requires_reboot: bool
    risk_of_breakage: Literal["low", "medium", "high"]


class AuditFinding(BaseModel):
    """One evidence-backed Linux finding in the existing Volve schema."""

    finding_id: str = Field(min_length=1, max_length=64)
    severity: Literal["critical", "high", "medium", "low"]
    category: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4_000)
    evidence_ids: list[str] = Field(min_length=1, max_length=8)
    remediation: Remediation


class AuditReport(BaseModel):
    """Structured report sent to Volve."""

    findings: list[AuditFinding] = Field(max_length=100)


HIGH_RISK_COMMAND_PATTERNS = (
    re.compile(
        r"\b(?:rm|rmdir|truncate|touch|mkdir|chmod|chown|chgrp|tee|mount|umount|reboot|shutdown)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bfind\b[^\n]*\s-delete\b", re.IGNORECASE),
    re.compile(r"\b(?:mkfs(?:\.\w+)?|wipefs|shred|dd)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:dnf|yum|apt|apt-get|rpm|dpkg)\s+"
        r"(?:install|update|upgrade|remove|erase|purge|autoremove|reinstall|downgrade)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bsystemctl\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\b", re.IGNORECASE),
    re.compile(r"\b(?:docker|podman)\s+(?:run|rm|stop|start|restart|exec|create|pull|push)\b", re.IGNORECASE),
    re.compile(r"\bsed\b[^\n]*\s-i(?:\s|$)", re.IGNORECASE),
    re.compile(r"(?:^|\s)>{1,2}\s*[^\s]"),
)


def build_vardlokk_agent(model: ChatModel) -> RequirementAgent:
    """Build the rule-driven, read-only Linux investigation agent."""
    return RequirementAgent(
        llm=model,
        tools=VARDLOKK_DIAGNOSTIC_TOOLS,
        name="Vardlokk",
        role="Linux system administrator's incident investigator",
        description="Investigates Linux alerts using bounded read-only diagnostic tools.",
        instructions=[
            "Investigate the supplied Linux alert and identify a root cause only when the evidence supports it.",
            "You are strictly read-only. The available tools collect telemetry; never attempt a state change.",
            (
                "The alert is a hypothesis, not proof. Confirm it with host evidence and call out facts you could not verify."
            ),
            (
                "Use inspect_directory_usage for storage pressure and inspect_systemd_unit "
                "for service failures when relevant."
            ),
            "Do not scan unrelated paths or units. Each diagnostic tool is bounded and may be used only a few times.",
            (
                "Every finding must cite one or more evidence IDs returned by diagnostic tools. "
                "Never invent evidence IDs."
            ),
            "Storage findings must cite host.filesystems evidence; when a directory scan is available, cite that too.",
            (
                "Memory or swap findings must cite host.memory or host.swap evidence. "
                "Service findings must cite systemd_unit evidence."
            ),
            "Remediation commands are recommendations for an administrator to review; Vardlokk cannot execute them.",
            (
                "Never recommend broad deletion, recursive deletion, or destructive commands. "
                "Prefer a safe inspection step over speculative cleanup."
            ),
            (
                "The risk field is a conservative estimate; broad or destructive commands are "
                "disallowed, not merely high-risk."
            ),
            (
                "If root cause cannot be established, return a limited finding describing "
                "what is verified and what remains unknown."
            ),
        ],
        requirements=[
            ConditionalRequirement(
                collect_host_snapshot,
                min_invocations=1,
                max_invocations=1,
                reason="A current host snapshot is required before reporting.",
            ),
            ConditionalRequirement(inspect_directory_usage, max_invocations=4),
            ConditionalRequirement(inspect_systemd_unit, max_invocations=4),
        ],
    )


def materialize_report(report: AuditReport, steps: list[object]) -> dict[str, object]:
    """Resolve model-selected evidence IDs to exact tool text for Volve."""
    evidence_by_id: dict[str, dict[str, str]] = {}
    incomplete_diagnostics = False
    for step in steps:
        tool = getattr(step, "tool", None)
        tool_name = getattr(tool, "name", "")
        if tool_name in {item.name for item in VARDLOKK_DIAGNOSTIC_TOOLS}:
            output = getattr(step, "output", "")
            if not isinstance(output, str):
                get_text_content = getattr(output, "get_text_content", None)
                output = get_text_content() if callable(get_text_content) else ""
            try:
                tool_result = json.loads(output)
            except (TypeError, json.JSONDecodeError):
                continue
            command_results: list[object] = []
            if tool_name == "collect_host_snapshot" and isinstance(tool_result, dict):
                command_results.append(tool_result.get("filesystems"))
            elif tool_name == "inspect_directory_usage":
                command_results.append(tool_result)
            elif tool_name == "inspect_systemd_unit" and isinstance(tool_result, dict):
                command_results.extend((tool_result.get("status"), tool_result.get("journal")))
            if any(
                not isinstance(result, dict) or result.get("returncode") != 0
                for result in command_results
            ):
                incomplete_diagnostics = True
            records = tool_result.get("evidence", []) if isinstance(tool_result, dict) else []
            if isinstance(records, list):
                for record in records:
                    if (
                        isinstance(record, dict)
                        and isinstance(record.get("id"), str)
                        and isinstance(record.get("kind"), str)
                        and isinstance(record.get("content"), str)
                        and record["content"].strip()
                    ):
                        evidence_by_id[record["id"]] = {
                            "kind": record["kind"],
                            "content": record["content"].strip(),
                        }

    if not evidence_by_id:
        raise ValueError("The report cannot be accepted because no diagnostic tool produced evidence.")

    findings: list[dict[str, object]] = []
    for finding in report.findings:
        evidence_ids = list(dict.fromkeys(finding.evidence_ids))
        missing = [evidence_id for evidence_id in evidence_ids if evidence_id not in evidence_by_id]
        if missing:
            raise ValueError(
                f"Finding {finding.finding_id!r} cites unknown evidence IDs: {', '.join(missing)}."
            )
        claim_text = " ".join((finding.category, finding.title, finding.description)).casefold()
        required_kinds: list[str] = []
        optional_kinds: list[str] = []
        if any(word in claim_text for word in ("storage", "disk", "filesystem", "file system", "space")):
            required_kinds.append("filesystem")
            optional_kinds.append("directory_usage")
        if "swap" in claim_text:
            required_kinds.append("swap")
        if "memory" in claim_text:
            required_kinds.append("memory")
        if any(word in claim_text for word in ("service", "systemd", "unit")):
            required_kinds.extend(("systemd_status", "systemd_journal"))

        for kind in required_kinds:
            source_ids = [item for item, value in evidence_by_id.items() if value["kind"] == kind]
            if not source_ids:
                # A service result can be established by either the unit state or journal.
                if kind == "systemd_journal" and any(
                    value["kind"] == "systemd_status" for value in evidence_by_id.values()
                ):
                    continue
                if kind == "systemd_status" and any(
                    value["kind"] == "systemd_journal" for value in evidence_by_id.values()
                ):
                    continue
                raise ValueError(f"Finding {finding.finding_id!r} requires {kind} evidence, but none was collected.")
            evidence_ids = list(dict.fromkeys(source_ids + evidence_ids))

        for kind in optional_kinds:
            source_ids = [item for item, value in evidence_by_id.items() if value["kind"] == kind]
            evidence_ids = list(dict.fromkeys(evidence_ids + source_ids))

        commands = finding.remediation.commands
        contains_destructive_command = any(
            pattern.search(command) for command in commands for pattern in HIGH_RISK_COMMAND_PATTERNS
        )
        finding_data = finding.model_dump(exclude={"evidence_ids"}, mode="json")
        finding_data["local_evidence"] = "\n".join(evidence_by_id[item]["content"] for item in evidence_ids)
        if contains_destructive_command:
            finding_data["remediation"]["commands"] = []
            finding_data["remediation"]["risk_of_breakage"] = "high"
            finding_data["description"] += (
                " Vardlokk omitted the proposed remediation commands because they included broad or "
                "destructive operations; administrator review is required."
            )
        if incomplete_diagnostics:
            finding_data["description"] += (
                " One or more diagnostics returned a non-zero status or partial output, "
                "so their totals may be incomplete."
            )
        findings.append(finding_data)
    return {"findings": findings}

