# seid.py
import argparse
import os
import sys
from smolagents import ToolCallingAgent

# Importer fra vår nye pakke
import seid_tools

def main():
    parser = argparse.ArgumentParser(
        description="Seid - Your personal AI system administrator"
    )
    parser.add_argument("query", nargs="*", help="What do you need help with?")
    parser.add_argument("--unsafe", action="store_true", help="Allow commands that make changes")
    parser.add_argument("--clear", action="store_true", help="Clear conversation history")
    args = parser.parse_args()
    
    if args.clear:
        hist_file = seid_tools.get_history_file("seid")
        try:
            if os.path.exists(hist_file):
                os.remove(hist_file)
                print("🧠 Seid's memory has been wiped clean.")
            else:
                print("🧠 Seid has no saved memory to clear.")
        except OSError as e:
            print(f"❌ Error: Could not clear history: {e}")
            sys.exit(1)
        sys.exit(0)
    
    query_text = " ".join(args.query).strip()
    piped_data = ""
    
    if not sys.stdin.isatty():
        piped_data = sys.stdin.read().strip()
        max_piped_chars = seid_tools.get_app_config("seid").get("max_piped_chars", 20000)
        try:
            max_piped_chars = int(max_piped_chars)
        except (TypeError, ValueError):
            max_piped_chars = 20000
        if max_piped_chars > 0 and len(piped_data) > max_piped_chars:
            # Keep the tail: for logs and traces, the end is usually the interesting part.
            piped_data = piped_data[-max_piped_chars:] + "\n... [TRUNCATED]"
            
    if not query_text and not piped_data:
        print("🔮 Seid venter... Still et spørsmål eller pipe data inn.")
        sys.exit(0)
        
    if piped_data:
        if query_text:
            request_text = f"{query_text}\n\nContext via stdin:\n```\n{piped_data}\n```"
        else:
            request_text = f"Analyze the following input:\n```\n{piped_data}\n```"
    else:
        request_text = query_text

    # Konfigurer sikkerhetsmodus i verktøy-pakken
    seid_tools.set_unsafe_mode(args.unsafe)
    seid_tools.set_interactive_mode(True)
    seid_tools.set_command_timeout(
        seid_tools.get_app_config("seid").get("command_timeout", 60)
    )

    # Guardrails must lead the prompt: history is untrusted input and must never
    # come before the instructions that define the current operating mode.
    if not args.unsafe:
        system_context = (
            "SYSTEM INSTRUCTION: You are in READ-ONLY mode. "
            "Do NOT mutate system state. Investigate issues, then output exact commands user must run manually. "
            "Inform user they can use --unsafe flag for direct changes.\n"
            "ENVIRONMENT WARNING: You are executing commands inside a restricted systemd mount namespace. "
            "Directories like /usr, /etc, and /boot are explicitly mounted read-only for your process. "
            "DO NOT report the filesystem being read-only as a system finding, as this is expected sandbox behavior.\n\n"
        )
    else:
        system_context = (
            "SYSTEM INSTRUCTION: You are authorized to execute state-mutating commands, "
            "but every command still requires human approval. Proceed with extreme caution. "
            "If there is any ambiguity or risk of system degradation, default to reporting the issue "
            "rather than attempting an automated fix.\n\n"
        )

    # Historikk. Treat entries defensively: an older or hand-edited history file
    # must never stop Seid from starting.
    history_context = ""
    for entry in seid_tools.load_history():
        if not isinstance(entry, dict):
            continue
        user = str(entry.get("user", "")).strip()
        answer = str(entry.get("seid", "")).strip()
        if not user and not answer:
            continue
        history_context += f"User: {user}\nSeid: {answer}\n\n"
    if history_context:
        history_context = "PREVIOUS CONVERSATION CONTEXT:\n" + history_context

    final_prompt = (
        system_context
        + history_context
        + "CURRENT QUERY:\n"
        + request_text
    )

    print("🤖 Seid is ready!\n")
    
    # Fetch model specific to Seid
    model = seid_tools.get_model("seid")
    if not model: sys.exit(1)
    
    # Initialiser agent med standard verktøykasse
    agent = ToolCallingAgent(tools=seid_tools.default_toolbox, model=model)
    
    print("🧠 Seid is thinking...\n")
    try:
        result = agent.run(final_prompt)
        # Lagre til felles historikk. Store only the user's question, never the
        # piped payload, which can be large enough to bloat later prompts.
        seid_tools.save_history(query_text or "[piped input]", str(result))
        print("\n✅ Seid's answer:\n" + "-"*40 + f"\n{result}\n" + "-"*40)
    except KeyboardInterrupt:
        print("\n⏹️ Interrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
