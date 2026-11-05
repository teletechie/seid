"""Vardlokk: BeeAI-based, read-only Linux incident investigator."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from beeai_framework.errors import FrameworkError

import seid_tools
from seid_tools.linux_diagnostics import set_diagnostic_timeout
from vardlokk_agent import AuditReport, build_vardlokk_agent, materialize_report


SUPPORTED_SCOPES = ("general", "security", "network", "performance", "investigate", "cis-rhel")
DEFAULT_MAX_ITERATIONS = 16
MAX_MAX_ITERATIONS = 40


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse Vardlokk arguments while keeping the existing CLI interface."""
    parser = argparse.ArgumentParser(description="Vardlokk - read-only Linux incident investigator")
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--scope", type=str.lower, choices=SUPPORTED_SCOPES, default="general")
    parser.add_argument(
        "--debug-payload",
        action="store_true",
        help="Print the final JSON payload instead of sending it to Volve",
    )
    parser.add_argument("--context", default="", help="Alert text for the investigate scope")
    parser.add_argument("--model", default="", help="Override the configured model ID for this run")
    args = parser.parse_args(argv)
    if args.unsafe:
        parser.error("Vardlokk is always read-only; --unsafe is not supported.")
    if args.scope == "investigate" and not args.context.strip():
        parser.error("--scope investigate requires a non-empty --context argument.")
    return args


def build_prompt(scope: str, context: str) -> str:
    """Build the incident request; tools and system rules enforce read-only behavior."""
    capabilities = (
        "Available evidence is limited to a host snapshot, allowlisted directory-usage scans, "
        "and read-only systemd/journal queries. Do not imply a comprehensive security, network, "
        "or compliance audit from this prototype's limited tools. "
    )
    if scope == "investigate":
        return capabilities + f"Investigate this alert on the current Linux host: {context.strip()}"
    scope_descriptions = {
        "general": "Perform a concise baseline assessment of host health and likely operational risks.",
        "security": "Assess host security posture using available host and service evidence.",
        "network": "Investigate host network health using available evidence.",
        "performance": "Investigate current host performance and resource pressure.",
        "cis-rhel": (
            "Assess available evidence relevant to a CIS-style RHEL baseline; "
            "do not claim full compliance coverage."
        ),
    }
    return capabilities + scope_descriptions[scope]


async def run_investigation(
    args: argparse.Namespace, config: dict[str, Any]
) -> tuple[AuditReport, list[object], str]:
    """Run BeeAI's managed agent loop and validate report evidence."""
    set_diagnostic_timeout(config.get("command_timeout", 60))
    model = seid_tools.get_beeai_model("vardlokk", args.model)
    agent = build_vardlokk_agent(model)
    print(f"👁 Vardlokk starting audit (Scope: {args.scope}, Model: {model.model_id})...\n")
    try:
        max_iterations = int(config.get("max_iterations", DEFAULT_MAX_ITERATIONS))
    except (TypeError, ValueError):
        max_iterations = DEFAULT_MAX_ITERATIONS
    max_iterations = min(max(1, max_iterations), MAX_MAX_ITERATIONS)
    response = await agent.run(
        build_prompt(args.scope, args.context),
        expected_output=AuditReport,
        max_iterations=max_iterations,
        total_max_retries=3,
        max_retries_per_step=1,
    )
    report = response.output_structured
    if not isinstance(report, AuditReport):
        raise ValueError("BeeAI did not return a structured Vardlokk report.")
    return report, response.state.steps, model.model_id


def build_payload(scope: str, report: AuditReport, steps: list[object]) -> dict[str, Any]:
    """Map BeeAI's typed report to the stable Volve payload."""
    return {
        "agent_metadata": {
            "hostname": socket.gethostname(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scope": scope,
        },
        "audit_data": materialize_report(report, steps),
    }


def send_to_volve(payload: dict[str, Any], config: dict[str, Any]) -> None:
    """Send the validated report to Volve using the existing Bearer-token API."""
    api_url = config.get("volve_api_url")
    token = config.get("volve_agent_token")
    if not api_url or not token:
        raise ValueError("Volve API URL or agent token is missing from Vardlokk configuration.")

    request = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    context = ssl.create_default_context()
    verify_ssl = config.get("volve_verify_ssl", True)
    if str(verify_ssl).lower() in ("false", "0", "no"):
        print("⚠ Security Warning: SSL certificate verification is disabled via configuration.")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        if response.status not in (200, 201, 202):
            raise RuntimeError(f"Volve returned unexpected status code {response.status}.")
    print("✅ Report successfully delivered to Volve.")


def main(argv: list[str] | None = None) -> int:
    """Run one read-only investigation and deliver its validated report."""
    args = parse_args(argv)
    config = seid_tools.get_app_config("vardlokk")
    try:
        report, steps, _model_id = asyncio.run(run_investigation(args, config))
        payload = build_payload(args.scope, report, steps)
        print("\n📊 AUDIT REPORT:")
        print(json.dumps(payload["audit_data"], indent=2))
        if args.debug_payload:
            print("\n🐛 DEBUG MODE: Skipping Volve API. Final payload:")
            print(json.dumps(payload, indent=2))
        else:
            send_to_volve(payload, config)
        return 0
    except KeyboardInterrupt:
        print("\n⏹ Vardlokk interrupted by operator.")
        return 130
    except (FrameworkError, urllib.error.URLError, ValueError, RuntimeError) as error:
        print(f"\n❌ Vardlokk failed: {error}")
        return 1
    except Exception as error:
        print(f"\n❌ Unexpected Vardlokk error: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

