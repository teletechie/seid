# vardlokk.py
import sys
import argparse
import json
import socket
import urllib.request
import urllib.error
import re
import ssl
from datetime import datetime, timezone
from smolagents import ToolCallingAgent

# Import common tools
import seid_tools

def main():
    parser = argparse.ArgumentParser(
        description="Vardlokk - Automated AI System Auditor"
    )
    # Vardlokk should primarily run in safe mode, but we keep the option from seid
    parser.add_argument("--unsafe", action="store_true", help="Allow auditor to make changes (not recommended)")
    parser.add_argument("--scope", default="general", help="Audit scope (e.g., security, network, performance, investigate)")
    parser.add_argument("--debug-payload", action="store_true", help="Print the final JSON payload to the terminal instead of sending it to Volve")
    parser.add_argument("--context", type=str, default="", help="Context or alert message for the investigate scope")
    args = parser.parse_args()

    # Configure security mode
    seid_tools.set_unsafe_mode(args.unsafe)
    seid_tools.set_interactive_mode(False)
    
    # Vardlokk System Prompt - Define auditor role
    vardlokk_prompt = (
        "You are Vardlokk, an automated AI system auditor. Your primary objective is to inspect the system state, "
        "identify potential issues, misconfigurations, pending patches, or security vulnerabilities, and propose actionable remediations.\n\n"
        "Utilize the provided tools to actively gather necessary system telemetry and information. There is a limit of 40 tool calls, but try run shorter than that\n\n"
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
        "CRITICAL SYSTEM INSTRUCTION: You are a strict data-output engine. "
        "When your audit is complete, you MUST submit your report by invoking the 'final_answer' tool. "
        "You are FORBIDDEN from outputting any conversational text, pleasantries, summaries, or preamble before or after the tool call. "
        "Your ENTIRE response MUST consist SOLELY of the exact text 'Action:' immediately followed by the raw JSON object. "
        "EXPECTED EXACT FORMAT:\n"
        "Action:\n"
        "{\n"
        '  "name": "final_answer",\n'
        '  "arguments": {\n'
        '    "answer": "{\\"findings\\": [{\\"finding_id\\": \\"CVE-2026-1234\\", \\"severity\\": \\"critical\\", \\"category\\": \\"security\\", \\"title\\": \\"Short description\\", \\"description\\": \\"Detailed explanation.\\", \\"local_evidence\\": \\"Why this applies.\\", \\"remediation\\": {\\"action_type\\": \\"cli_commands\\", \\"commands\\": [\\"dnf update -y nginx\\"], \\"requires_reboot\\": false, \\"risk_of_breakage\\": \\"low\\"}}]}"\n'
        '  }\n'
        "}\n"
    )

    vardlokk_prompt += (
        "CRITICAL CONSTRAINTS FOR PERFORMANCE:\n"
        "- Use strict JSON tool calls without any extra text.\n"
        "- When checking disk space, ALWAYS ignore loop devices and tmpfs (e.g., use 'df -h -x squashfs -x tmpfs').\n"
        "- As soon as you have an answer with high confidence, generate your final JSON report and stop."
    )

    # Fetch model specific to Vardlokk
    model = seid_tools.get_model("vardlokk")
    if not model: sys.exit(1)
    
    # Use the same tools as Seid
    agent = ToolCallingAgent(tools=seid_tools.default_toolbox, model=model, max_steps=40)
    
    print(f"👁 Vardlokk starting audit (Scope: {args.scope})...\n")
    
    try:
        # Vardlokk runs without user input (query)
        result = agent.run(vardlokk_prompt)
        
        print("\n📊 RAW AUDIT REPORT GENERATED:")
        print("="*60)
        print(result)
        print("="*60)
        
        # TODO: Get raw JSON in a more brute force way here?
        # result = re.search(r'\{[\s\S]*\}', str(result))
       
        # Parse LLM's output to ensure it is valid JSON
        # Clean up potential markdown formatting wrapping the JSON
        clean_result = str(result).strip()
        if clean_result.startswith("```json"):
            clean_result = clean_result[7:-3].strip()
        elif clean_result.startswith("```"):
            clean_result = clean_result[3:-3].strip()

        audit_data = json.loads(clean_result)
        
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
            cfg = seid_tools.config.get_app_config("vardlokk")
            api_url = cfg.get("volve_api_url")
            token = cfg.get("volve_agent_token")
            
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

    except json.JSONDecodeError:
        print("\n❌ Error: Vardlokk did not return valid JSON. Failed to parse output.")
        print("Raw output:\n", result)
    except urllib.error.URLError as e:
        print(f"\n❌ Network error while sending to Volve: {e}")
    except KeyboardInterrupt:
        print("\n⏹ Vardlokk interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error during audit: {e}")

if __name__ == "__main__":
    main()
