"""
Vardlokk: Automated AI System Auditor

This script runs asynchronously (e.g., triggered by Nagios or cron). 
It takes a context or scope, uses an LLM agent to investigate the system 
via Tool Calling, and outputs a strict JSON report. The report is then 
delivered over the network to the Volve dashboard.
"""

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

from smolagents import ToolCallingAgent
import seid_tools

def build_system_prompt(args) -> str:
    """
    Constructs the system prompt dynamically based on the requested scope,
    safety mode, and strict JSON output requirements.
    """
    # 1. Base Role
    prompt = (
        "You are Vardlokk, an automated AI system auditor. Your primary objective is to inspect the system state, "
        "identify potential issues, misconfigurations, pending patches, or security vulnerabilities, and propose actionable remediations.\n\n"
        "Utilize the provided tools to actively gather necessary system telemetry. "
        "There is a limit of 40 tool calls, but aim to complete your investigation in as few steps as possible.\n\n"
        f"CURRENT AUDIT SCOPE: {args.scope.upper()}\n"
    )

    # 2. Scope Definition
    match args.scope.upper():
        case "GENERAL":
            prompt += "Task: Perform a broad baseline check of system health, disk usage, memory, network, and performance.\n\n"
        case "SECURITY" | "NETWORK" | "PERFORMANCE":
            prompt += f"Task: Perform a baseline check strictly centered on {args.scope.lower()}.\n\n"
        case "INVESTIGATE":
            if not args.context:
                print("❌ Error: --scope investigate requires a --context argument.")
                sys.exit(1)
            prompt += f"Task: Focus ONLY on diagnosing this specific alert/context: '{args.context}'. Do not perform general health checks.\n\n"
        case "CIS-RHEL":
            prompt += "Task: Audit the system against CIS RHEL benchmarks. Focus on file permissions, SSH config, and auditd rules.\n\n"
        case _:
            print(f"❌ Error: Unknown scope '{args.scope}'")
            sys.exit(1)

    # 3. Guardrails & Environment Context
    if not args.unsafe:
        prompt += (
            "SYSTEM INSTRUCTION: You are operating in STRICT READ-ONLY mode. You must NOT mutate system state. "
            "Your role is strictly to analyze and report. Your final report must include exact, ready-to-execute "
            "CLI commands that a human administrator can run to resolve the identified issues.\n\n"
            "ENVIRONMENT WARNING: You are executing commands inside a restricted systemd mount namespace. "
            "Directories like /usr, /etc, and /boot are explicitly mounted read-only for your process. "
            "DO NOT report the filesystem being read-only as a system finding or error, as this is expected sandbox behavior.\n\n"
        )
    else:
        prompt += (
            "SYSTEM INSTRUCTION: You are authorized to execute state-mutating commands to remediate critical issues. "
            "Proceed with extreme caution. If there is any ambiguity or risk of system degradation, "
            "default to reporting the issue rather than attempting an automated fix.\n\n"
        )

    # 4. Enforce JSON Output Schema
    # LLMs frequently suffer from "Instruction Amnesia" and output markdown or conversational text.
    # This strict formatting block forces the agent to behave like an API endpoint.
    prompt += """CRITICAL SYSTEM INSTRUCTION: You are a strict data-output engine.
When your audit is complete, you MUST submit your report by invoking the 'final_answer' tool.
You are FORBIDDEN from outputting any conversational text, pleasantries, summaries, or preamble.
Your ENTIRE response MUST consist SOLELY of the exact text 'Action:' immediately followed by the raw JSON object.

EXPECTED EXACT FORMAT:
Action:
{
  "name": "final_answer",
  "arguments": {
    "answer": "{\\"findings\\": [{\\"finding_id\\": \\"CVE-2026-1234\\", \\"severity\\": \\"critical\\", \\"category\\": \\"security\\", \\"title\\": \\"Short description\\", \\"description\\": \\"Detailed explanation.\\", \\"local_evidence\\": \\"Why this applies.\\", \\"remediation\\": {\\"action_type\\": \\"cli_commands\\", \\"commands\\": [\\"dnf update -y nginx\\"], \\"requires_reboot\\": false, \\"risk_of_breakage\\": \\"low\\"}}]}"
  }
}

CRITICAL CONSTRAINTS FOR PERFORMANCE:
- Use strict JSON tool calls without any extra text.
- When checking disk space, ALWAYS ignore loop devices and tmpfs (e.g., use 'df -h -x squashfs -x tmpfs').
- As soon as you have an answer with high confidence, generate your final JSON report and stop.
"""
    return prompt

def extract_json_from_result(result_str: str) -> dict:
    """
    Brute-force JSON extraction. Even with strict prompts, LLMs occasionally wrap 
    JSON in markdown blockticks or add conversational preambles.
    """
    clean_result = result_str.strip()
    
    # Use regex to find the first `{` and the last `}` to isolate the JSON object
    match = re.search(r'\{[\s\S]*\}', clean_result)
    if match:
        clean_result = match.group(0)
        
    return json.loads(clean_result)

def main():
    parser = argparse.ArgumentParser(description="Vardlokk - Automated AI System Auditor")
    parser.add_argument("--unsafe", action="store_true", help="Allow auditor to make changes (not recommended)")
    parser.add_argument("--scope", default="general", help="Audit scope (e.g., security, network, performance, investigate)")
    parser.add_argument("--debug-payload", action="store_true", help="Print the final JSON payload to terminal instead of sending it to Volve")
    parser.add_argument("--context", type=str, default="", help="Context or alert message for the 'investigate' scope")
    args = parser.parse_args()

    # Configure security and interaction modes
    seid_tools.set_unsafe_mode(args.unsafe)
    seid_tools.set_interactive_mode(False)
    
    vardlokk_prompt = build_system_prompt(args)

    # Fetch model specific to Vardlokk (e.g., lightweight model for fast background tasks)
    model = seid_tools.get_model("vardlokk")
    if not model: 
        print("❌ Error: Could not load model configuration.")
        sys.exit(1)
    
    agent = ToolCallingAgent(tools=seid_tools.default_toolbox, model=model, max_steps=40)
    
    print(f"👁 Vardlokk starting audit (Scope: {args.scope.upper()})...\n")
    
    try:
        # Run the autonomous loop
        result = agent.run(vardlokk_prompt)
        
        print("\n📊 RAW AUDIT REPORT GENERATED:")
        print("="*60)
        print(result)
        print("="*60)
        
        # Parse the output safely
        audit_data = extract_json_from_result(str(result))
        
        # Build the payload envelope for Volve
        payload = {
            "agent_metadata": {
                "hostname": socket.gethostname(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "scope": args.scope
            },
            "audit_data": audit_data
        }
        
        if args.debug_payload:
            print("\n🐛 DEBUG MODE: Skipping Volve API. Printing payload to terminal:")
            print(json.dumps(payload, indent=2))
            sys.exit(0)
            
        json_payload = json.dumps(payload).encode('utf-8')
        
        # Prepare network delivery
        cfg = seid_tools.config.get_app_config("vardlokk")
        api_url = cfg.get("volve_api_url")
        token = cfg.get("volve_agent_token")
        
        # Secure by default: fallback to True if the key is missing
        verify_ssl = cfg.get("volve_verify_ssl", True)
        
        if not api_url or not token:
            print("\n⚠ API URL or Token is missing in configuration. Printing final payload locally instead:")
            print(json.dumps(payload, indent=2))
            sys.exit(0)

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
        
        # Configure SSL based on the configuration file
        ctx = ssl.create_default_context()
        
        # Support both boolean True/False and string "true"/"false" from config files
        if str(verify_ssl).lower() in ("false", "0", "no"):
            print("⚠ Security Warning: SSL certificate verification is disabled via configuration.")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            if response.status in (200, 201, 202):
                print("✅ Report successfully delivered to Volve.")
            else:
                print(f"⚠ Volve returned status code {response.status}")

    except json.JSONDecodeError:
        print("\n❌ Error: Vardlokk did not return valid JSON. Failed to parse output.")
        print(f"Raw output attempt:\n{result}")
    except urllib.error.URLError as e:
        print(f"\n❌ Network error while sending to Volve: {e}")
    except KeyboardInterrupt:
        print("\n⏹ Vardlokk interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error during audit: {e}")

if __name__ == "__main__":
    main()