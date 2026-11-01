"""Read-only, Linux-specific diagnostic tools for Vardlokk."""

import hashlib
import json
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from beeai_framework.tools import StringToolOutput, tool

COMMAND_TIMEOUT = 60
MAX_TOOL_OUTPUT = 8_000
MAX_JOURNAL_LINES = 200

# These are deliberately explicit: Vardlokk never receives an arbitrary path
# for recursive disk-usage scans or an arbitrary shell command.
DIRECTORY_SCAN_PATHS = ("/", "/var", "/var/log", "/var/lib", "/home", "/opt", "/srv", "/tmp")
SYSTEMD_UNIT_PATTERN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,127}")


def set_diagnostic_timeout(seconds: int) -> None:
    """Set a positive timeout for the fixed read-only diagnostic commands."""
    global COMMAND_TIMEOUT
    try:
        timeout = int(seconds)
    except (TypeError, ValueError):
        return
    if timeout > 0:
        COMMAND_TIMEOUT = timeout


def _run_diagnostic(argv: list[str]) -> dict[str, object]:
    """Run a fixed diagnostic command without a shell and bound its output."""
    try:
        result = subprocess.run(
            argv,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
        )
        stdout = result.stdout[:MAX_TOOL_OUTPUT]
        stderr = result.stderr[:2_000]
        if len(result.stdout) > MAX_TOOL_OUTPUT:
            stdout += "\n[output truncated]"
        return {"returncode": result.returncode, "stdout": stdout, "stderr": stderr}
    except subprocess.TimeoutExpired:
        return {"error": f"Diagnostic command timed out after {COMMAND_TIMEOUT}s."}
    except FileNotFoundError as error:
        return {"error": f"Required diagnostic utility is unavailable: {error.filename}"}
    except OSError as error:
        return {"error": f"Diagnostic command failed: {error}"}


def _read_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        fields = value.split()
        if fields and fields[0].isdigit():
            # Linux reports these values in kB; normalize to bytes.
            values[key] = int(fields[0]) * (1024 if len(fields) > 1 and fields[1] == "kB" else 1)
    return values


def _read_swap_devices() -> list[dict[str, str]]:
    lines = Path("/proc/swaps").read_text(encoding="utf-8").splitlines()
    devices = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) >= 5:
            devices.append({"filename": fields[0], "type": fields[1], "size_kib": fields[2], "used_kib": fields[3]})
    return devices


def _evidence_record(kind: str, content: str) -> dict[str, str] | None:
    """Give an exact diagnostic excerpt a stable, content-addressed ID."""
    excerpt = content.strip()
    if not excerpt:
        return None
    digest = hashlib.sha256(f"{kind}:{excerpt}".encode("utf-8")).hexdigest()[:12]
    return {"id": digest, "kind": kind, "content": excerpt}


def _command_evidence(result: dict[str, object]) -> str:
    """Preserve command status and both output streams in the evidence excerpt."""
    return (
        f"Exit status: {result.get('returncode', 'unavailable')}\n"
        f"Error: {result.get('error', '')}\n"
        f"STDOUT:\n{result.get('stdout', '')}\n"
        f"STDERR:\n{result.get('stderr', '')}"
    )


@tool
def collect_host_snapshot() -> StringToolOutput:
    """Collect a fixed read-only Linux snapshot: OS, uptime/load, memory, swap and mounted filesystem usage."""
    try:
        meminfo = _read_meminfo()
        swap_total = meminfo.get("SwapTotal", 0)
        swap_free = meminfo.get("SwapFree", 0)
        load_average = os.getloadavg()
        uptime_seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
        release = platform.freedesktop_os_release()
        swap_devices = _read_swap_devices()
    except (OSError, ValueError, IndexError) as error:
        return StringToolOutput(result=json.dumps({"error": f"Could not collect host snapshot: {error}"}))

    filesystem_usage = _run_diagnostic(["df", "-h", "-x", "squashfs", "-x", "tmpfs", "-x", "devtmpfs"])
    memory_evidence = (
        f"MemTotalBytes={meminfo.get('MemTotal')}; "
        f"MemAvailableBytes={meminfo.get('MemAvailable')}"
    )
    swap_evidence = (
        f"SwapTotalBytes={swap_total}; SwapFreeBytes={swap_free}; "
        f"SwapUsedPercent={round((swap_total - swap_free) * 100 / swap_total, 1) if swap_total else 0}"
    )
    evidence = [
        _evidence_record("filesystem", _command_evidence(filesystem_usage))
        if "returncode" in filesystem_usage
        else None,
        _evidence_record("memory", memory_evidence),
        _evidence_record("swap", swap_evidence),
        _evidence_record("load", f"LoadAverage1_5_15={load_average}"),
    ]
    snapshot = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(),
        "os": {"name": release.get("NAME"), "version": release.get("VERSION_ID"), "id": release.get("ID")},
        "kernel": platform.release(),
        "uptime_seconds": round(uptime_seconds),
        "load_average_1_5_15": [round(value, 2) for value in load_average],
        "memory_bytes": {
            "total": meminfo.get("MemTotal"),
            "available": meminfo.get("MemAvailable"),
            "swap_total": swap_total,
            "swap_free": swap_free,
            "swap_used_percent": round((swap_total - swap_free) * 100 / swap_total, 1) if swap_total else 0,
        },
        "swap_devices": swap_devices,
        "filesystems": filesystem_usage,
        "evidence": [record for record in evidence if record is not None],
    }
    return StringToolOutput(result=json.dumps(snapshot, indent=2, sort_keys=True))


@tool
def inspect_directory_usage(
    path: Literal["/", "/var", "/var/log", "/var/lib", "/home", "/opt", "/srv", "/tmp"]
) -> StringToolOutput:
    """Measure immediate disk usage beneath one of the approved Linux system paths; this does not modify files."""
    if path not in DIRECTORY_SCAN_PATHS:
        return StringToolOutput(result=json.dumps({"error": "Path is not in the diagnostic allowlist."}))
    if not os.path.isdir(path):
        return StringToolOutput(result=json.dumps({"path": path, "error": "Directory does not exist on this host."}))

    result = _run_diagnostic(["du", "-x", "-h", "--max-depth=1", "--", path])
    record = _evidence_record("directory_usage", _command_evidence(result)) if "returncode" in result else None
    return StringToolOutput(
        result=json.dumps({"path": path, **result, "evidence": [record] if record else []}, indent=2)
    )


@tool
def inspect_systemd_unit(unit: str, journal_lines: int = 80) -> StringToolOutput:
    """Read a systemd unit's state and recent journal entries; never starts, stops or changes the unit."""
    if not SYSTEMD_UNIT_PATTERN.fullmatch(unit):
        return StringToolOutput(result=json.dumps({"error": "Invalid systemd unit name."}))
    if not 1 <= journal_lines <= MAX_JOURNAL_LINES:
        return StringToolOutput(
            result=json.dumps({"error": f"journal_lines must be between 1 and {MAX_JOURNAL_LINES}."})
        )

    properties = "Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp"
    status = _run_diagnostic(["systemctl", "show", "--no-pager", f"--property={properties}", "--", unit])
    journal = _run_diagnostic(
        ["journalctl", "--no-pager", "--output=short-iso", "--unit", unit, "--lines", str(journal_lines)]
    )
    evidence = [
        _evidence_record("systemd_status", _command_evidence(status)) if "returncode" in status else None,
        _evidence_record("systemd_journal", _command_evidence(journal)) if "returncode" in journal else None,
    ]
    return StringToolOutput(
        result=json.dumps(
            {"unit": unit, "status": status, "journal": journal, "evidence": [item for item in evidence if item]},
            indent=2,
        )
    )


VARDLOKK_DIAGNOSTIC_TOOLS = [
    collect_host_snapshot,
    inspect_directory_usage,
    inspect_systemd_unit,
]

