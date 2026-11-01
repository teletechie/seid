# vardlokk.py
import sys
import argparse
import json
import socket
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone
from smolagents import OpenAIServerModel, ToolCallingAgent

# Import common tools
import seid_tools


class ReportTolerantModel(OpenAIServerModel):
    """Accepts a bare findings report as the model's final answer.

    Quantized and distilled models frequently answer with the requested JSON
    document itself, for example {"findings": [...]}, instead of wrapping it in
    a 'final_answer' tool call. smolagents rejects that as a parse error and
    burns a step, which on slow local models can consume the whole audit budget.
    Rewrite such a response into the tool call the agent expects.

    Only reports that cite evidence from real tool output are accepted. Without
    that check the models stop at once and fill local_evidence with placeholders
    such as '[Output from df -h]', skipping the investigation entirely.
    """

    def parse_tool_calls(self, message):
        if not message.tool_calls and isinstance(message.content, str):
            try:
                report = extract_json_from_result(message.content)
            except json.JSONDecodeError:
                report = None
            if (
                isinstance(report, dict)
                and "findings" in report
                and has_grounded_evidence(report)
            ):
                message.content = json.dumps({
                    "name": "final_answer",
                    "arguments": {"answer": json.dumps(report)},
                })
        return super().parse_tool_calls(message)


def has_grounded_evidence(report: dict) -> bool:
    """Reports whether every finding cites evidence from actual tool output."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        return False
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        evidence = finding.get("local_evidence")
        if not isinstance(evidence, str):
            return False
        text = evidence.strip()
        if len(text) < 10 or text.startswith("["):
            return False
    return True


def extract_json_from_result(result_str: str) -> dict:
    """Extracts the first complete JSON object from the model output.

    Even with strict prompts, quantized models sometimes wrap JSON in markdown
    fences, add prose, or emit extra closing braces. raw_decode parses the first
    complete object and ignores whatever follows, instead of rejecting the whole
    report.
    """
    text = result_str.strip()
    start = text.find("{")
    if start == -1:
        raise json.JSONDecodeError("No JSON object found in model output", text, 0)

    data, _ = json.JSONDecoder().raw_decode(text, start)
    if not isinstance(data, dict):
        raise json.JSONDecodeError("Top-level JSON value is not an object", text, start)
    return data

def main():
    parser = argparse.ArgumentParser(
        description="Vardlokk - Automated AI System Auditor"
    )
    # Vardlokk should primarily run in safe mode, but we keep the option from seid
    parser.add_argument("--unsafe", action="store_true", help="Allow auditor to make changes (not recommended)")
    parser.add_argument("--scope", default="general", help="Audit scope (e.g., security, network, performance, investigate)")
    parser.add_argument("--debug-payload", action="store_true", help="Print the final JSON payload to the terminal instead of sending it to Volve")
    parser.add_argument("--context", type=str, default="", help="Context or alert message for the investigate scope")
    parser.add_argument("--model", type=str, default="", help="Override the configured model ID for this run")
    args = parser.parse_args()

    # Configure security mode
    seid_tools.set_unsafe_mode(args.unsafe)
    seid_tools.set_interactive_mode(False)
    seid_tools.set_command_timeout(
        seid_tools.get_app_config("vardlokk").get("command_timeout", 60)
    )
    
    # Vardlokk System Prompt - Define auditor role
    vardlokk_prompt = (
        "You are Vardlokk, an automated AI system auditor. Your primary objective is to inspect the system state, "
        "identify potential issues, misconfigurations, pending patches, or security vulnerabilities, and propose actionable remediations.\n\n"
        "Utilize the provided tools to actively gather necessary system telemetry and information. There is a limit of 40 tool calls, so aim to finish well below that.\n\n"
        f"Current audit scope: {args.scope.upper()}\n"
    )

    match args.scope.upper():
        case "GENERAL":
            vardlokk_prompt += "Perform a broad baseline check of system health, disk usage, memory, network and performance.\n\n"
        case "SECURITY" | "NETWORK" | "PERFORMANCE" :
            vardlokk_prompt += "Perform a baseline check centered on the given audit scope.\n\n"
        case "INVESTIGATE":
            if not args.context:
                print("❌ Error: --scope investigate requires a --context argument.")
                sys.exit(1) 
            vardlokk_prompt += f"Focus ONLY on diagnosing this alert: {args.context}. Do not perform general health checks.\n\n"
        case "CIS-RHEL":
            vardlokk_prompt += "Audit the system against CIS RHEL benchmarks. Focus on file permissions, SSH config, and auditd rules.\n\n"
        case _:
            print(f"Unknown scope: {args.scope}")
            sys.exit(1)
    
    if not args.unsafe:
        vardlokk_prompt += (
            "SYSTEM INSTRUCTION: You are operating in STRICT READ-ONLY mode. You must NOT mutate system state. "
            "Your role is strictly to analyze and report. Your final report must include the exact, ready-to-execute "
            "CLI commands that a human administrator can run to resolve the identified issues. "
            "IMPORTANT: You are executing commands inside a restricted systemd mount namespace. "
            "Directories like /usr, /etc, and /boot are explicitly mounted read-only for your process. "
            "DO NOT report the filesystem being read-only as a system finding or error, as this is expected sandbox behavior.\n\n"
        )
    else:
        vardlokk_prompt += (
            "SYSTEM INSTRUCTION: You are authorized to execute state-mutating commands to remediate critical issues. "
            "Proceed with extreme caution. If there is any ambiguity or risk of system degradation, "
            "default to reporting the issue rather than attempting an automated fix.\n\n"
        )

    # Enforce JSON output schema
    vardlokk_prompt += (
        "REPORTING INSTRUCTION: When your audit is complete, submit the report by calling the 'final_answer' tool "
        "exactly once. Call the tool directly. Do NOT write the tool call as text, and do not prefix your response "
        "with 'Action:', 'Thought:', or any other marker.\n"
        "The 'answer' argument must be a JSON object, serialised as a string, with this schema:\n"
        "{\"findings\": [{\"finding_id\": \"SHORT-ID\", \"severity\": \"critical|high|medium|low\", "
        "\"category\": \"storage|security|network|performance|packages\", \"title\": \"One line summary\", "
        "\"description\": \"Detailed explanation.\", \"local_evidence\": \"The command output that shows it.\", "
        "\"remediation\": {\"action_type\": \"cli_commands\", \"commands\": [\"exact command\"], "
        "\"requires_reboot\": false, \"risk_of_breakage\": \"low|medium|high\"}}]}\n"
        "If you found nothing worth reporting, call 'final_answer' with an empty findings list.\n"
        "Before reporting, you MUST have run diagnostic commands with the provided tools. "
        "Copy 'local_evidence' verbatim from the output you actually received. "
        "Never write placeholders such as '[Output from df -h]'.\n\n"
    )

    vardlokk_prompt += (
        "CONSTRAINTS:\n"
        "- Call tools directly instead of describing them in prose.\n"
        "- Only propose commands that exist on this system and that you have confirmed are available.\n"
        "- Never run destructive commands and never propose deleting data you have not inspected.\n"
        "- When checking disk space, ignore loop devices and tmpfs (e.g. 'df -h -x squashfs -x tmpfs').\n"
        "- As soon as you have an answer with high confidence, submit the final report and stop."
    )

    # Fetch model specific to Vardlokk
    model = seid_tools.get_model("vardlokk", args.model or None, ReportTolerantModel)
    if not model: sys.exit(1)
    
    # Use the same tools as Seid
    agent = ToolCallingAgent(tools=seid_tools.default_toolbox, model=model, max_steps=40)
    
    print(f"👁 Vardlokk starting audit (Scope: {args.scope}, Model: {model.model_id})...\n")
    
    result = None
    try:
        # Vardlokk runs without user input (query)
        result = agent.run(vardlokk_prompt)
        
        print("\n📊 RAW AUDIT REPORT GENERATED:")
        print("="*60)
        print(result)
        print("="*60)
        
        audit_data = extract_json_from_result(str(result))
        
        # Build the envelope for Volve
        payload = {
            "agent_metadata": {
                "hostname": socket.gethostname(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "scope": args.scope
            },
            "audit_data": audit_data
        }
        
        # Check debug flag before attempting network operations
        if args.debug_payload:
            print("\n🐛 DEBUG MODE: Skipping Volve API. Printing payload to terminal:")
            print(json.dumps(payload, indent=2))
        else:
            json_payload = json.dumps(payload).encode('utf-8')
            
            # Prepare the API call
            cfg = seid_tools.get_app_config("vardlokk")
            api_url = cfg.get("volve_api_url")
            token = cfg.get("volve_agent_token")
            # Secure by default: fall back to True if the key is missing.
            verify_ssl = cfg.get("volve_verify_ssl", True)
            
            if api_url and token:
                print("\n🚀 Sending audit report to Volve...")
                req = urllib.request.Request(
                    api_url, 
                    data=json_payload, 
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {token}'
                    },
                    method='POST'
                )
                ctx = ssl.create_default_context()
                # Support both boolean True/False and string "true"/"false".
                if str(verify_ssl).lower() in ("false", "0", "no"):
                    print("⚠ Security Warning: SSL certificate verification is disabled via configuration.")
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                    if response.status in (200, 201, 202):
                        print("✅ Report successfully delivered to Volve.")
                    else:
                        print(f"⚠ Volve returned status code {response.status}")
            else:
                print("\n⚠ API URL or Token is missing in configuration. Printing final payload locally instead:")
                print(json.dumps(payload, indent=2))

    except json.JSONDecodeError as e:
        print(f"\n❌ Error: Vardlokk did not return valid JSON: {e}")
        if result is not None:
            print(f"Raw output:\n{result}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"\n❌ Network error while sending to Volve: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹ Vardlokk interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error during audit: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

