# Seid

**Seid** (pronounced *said*) is a command-line AI system administrator tool designed to help you manage your Linux environment safely and efficiently. 

While **Seid** serves as your primary, interactive AI assistant in the terminal, the ecosystem also includes **Vardlokk** (an automated system auditor) and **Volve** (a centralized dashboard) for fleet-wide monitoring and remediation.

## Inspiration
The name **Seid** is derived from *seiðr*, an Old Norse practice of magic involving prophecy, trance states, and the manipulation of fate. Just as seiðr practitioners navigated unseen forces to alter reality, Seid helps system administrators navigate complex technical landscapes with foresight, precision, and control.

The extended toolset follows this mythological framework:
*   **Vardlokk:** Named after the ritual song used to draw in spirits and hidden knowledge. It investigates server alerts using bounded Linux diagnostics and reports evidence-backed findings.
*   **Volve:** Named after the seeress who interpreted the visions. Volve acts as the central GUI/Dashboard that receives Vardlokk's findings, presenting you with the big picture and actionable remediation steps.

## Architecture Overview
*   **Seid (Core CLI):** Your interactive, local AI sysadmin. Ask it to troubleshoot issues, read logs, or configure services directly from your terminal.
*   **Vardlokk (Automated Agent):** An alert-triggered Linux troubleshooter using BeeAI's requirement-driven agent and read-only diagnostic tools to generate structured reports.
*   **Volve (Dashboard API):** The central receiver for Vardlokk reports, allowing administrators to review findings and approve remediation commands across a fleet of servers.

## Features
- 🛡 **Read-Only Vardlokk**: Uses bounded Linux diagnostic tools and a read-only systemd service context; it has no arbitrary shell or mutation tools.
- 🔓 **Interactive Seid**: Seid can request human approval for commands; `--unsafe` never removes the approval prompt.
- 🤖 **Framework-Managed Agents**: Seid and Vardlokk use BeeAI's requirement-driven agent and typed tools.
- 🔍 **Custom Tools**: Includes built-in tools for running local CLI commands, reading files, and searching OS documentation.
- 🏢 **Enterprise Ready**: Hierarchical configuration, secure SSL handling, and structured JSON output for integrating into larger monitoring pipelines.

## Installation
Clone the repository:
  ```bash
  git clone https://github.com/teletechie/seid
  cd seid
  ```

Create a venv and install the dependencies:
```bash
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```
The BeeAI-based Seid and Vardlokk agents require Python 3.11 or newer.

To run the test suite, install the development dependencies and run pytest:

```bash
pip install -r requirements-dev.txt
pytest
```

Create a script to run seid, e.g. in /usr/local/bin:
```text
#!/bin/bash

exec /usr/local/seid/venv/bin/python /usr/local/seid/seid.py "$@"
```

Create a script to run vardlokk, e.g. in /usr/local/sbin:
```text
#!/bin/bash

# set this if you need python to find system ca certificate chains
# for your in house certificate authority. This path works for RHEL
export SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt

exec /usr/local/seid/venv/bin/python /usr/local/seid/vardlokk.py "$@"
```

### Local model with Ollama
Seid speaks to any OpenAI-compatible endpoint. The easiest setup is a local [Ollama](https://ollama.com) server with a model that supports native tool calling:

```bash
ollama pull granite3.3
```

Ollama serves models with a 4096-token context by default. That is too small once tool output and history are added, and the excess is truncated silently. Build a variant with a larger context instead of changing the daemon:

```bash
cat > Modelfile.granite16k <<'EOF'
FROM granite3.3:latest
PARAMETER num_ctx 16384
EOF
ollama create granite3.3-16k -f Modelfile.granite16k
```

Then set `model_id` to `granite3.3-16k:latest`, `model_api_base` to `http://localhost:11434/v1`, and `model_api_key` to any placeholder such as `not_needed`. If VRAM is tight, setting `OLLAMA_KV_CACHE_TYPE=q4_0` in the Ollama service shrinks the KV cache considerably at a small quality cost.

Larger models generally reason better, but check `ollama ps` after the first request. If the `PROCESSOR` column is not 100% GPU, part of the model is running on CPU and each agent step can take tens of seconds. That is tolerable for a short Seid question. The Vardlokk prototype is capped at 16 agent iterations by default.

## Configuration
The Seid ecosystem uses a hierarchical JSON configuration. The system looks for the configuration file in two locations, allowing user-specific overrides:

- /etc/seid/seid.conf (System-wide default)
- ~/.config/seid/seid.conf (User-level override)

The configuration file is divided into a common block for shared settings (like your local LLM endpoint) and application-specific blocks (seid and vardlokk) that can override global settings.

Example seid.conf:

```json
{
  "common": {
    "model_api_base": "http://localhost:11434/v1",
    "model_api_key": "not_needed",
    "model_id": "granite3.3-16k:latest",
    "command_timeout": 60
  },
  "seid": {
    "history_file": "~/.seid_history.json",
    "max_piped_chars": 20000
  },
  "vardlokk": {
    "volve_api_url": "http://localhost:8000/api/v1/audits",
    "volve_agent_token": "your_secure_token_here",
    "model_id": "granite3.3-16k:latest"
  }
}
```

Note on Security Contexts: `volve_verify_ssl` defaults to true if omitted. The example above uses plain HTTP on localhost, so no certificate settings are needed. Set `volve_verify_ssl` to false only if you use HTTPS with a self-signed certificate.

`command_timeout` sets the maximum number of seconds any single command the agent runs may take, and defaults to 60. Raise it if audits need slow commands such as `du` or `journalctl` over large logs. Put it in the `seid` or `vardlokk` block instead of `common` to give the two applications different limits.

If you run Volve behind a reverse proxy mounted at `/volve`, use `http://your-host/volve/api/v1/audits` instead. The localhost URL above is the direct uvicorn path and is the easiest starting point.

## Usage
### Seid (Interactive CLI)

Run Seid with a specific question or query:

```bash
python seid.py "How do I check disk usage?"
```

Pipe data into Seid for analysis:

```bash
journalctl -u nginx -n 50 | python seid.py "Why is the web server crashing?"
```

By default, Seid briefly explains why it wants to run each command and displays the command output after approval. Use `-q` or `--quiet` for the terse output mode:

```bash
python seid.py --quiet "Check disk usage on this host"
```

Allow system modifications (requires manual confirmation per command):

```bash
python seid.py --unsafe "Update the system and install htop"
```

### Vardlokk (Automated Auditor)
Run an automated audit on a specific scope (e.g., security, network, performance):

```bash
python vardlokk.py --scope security
```

Test the Vardlokk JSON output locally without sending the payload to the Volve API:

```bash
python vardlokk.py --scope general --debug-payload
```

Run Vardlokk to investigate a specific problem (e.g., triggered by a monitoring agent like Nagios):

```bash
python vardlokk.py --scope investigate --context "nagios alert: CRITICAL: /home is full" --debug-payload
```

### Volve (Dashboard API)
Volve receives Vardlokk's reports and serves the web dashboard. Install its dependencies and start it locally:

```bash
cd volve
pip install -r requirements.txt
export VOLVE_API_TOKEN="your_secure_token_here"
uvicorn main:app --host 127.0.0.1 --port 8000
```

The dashboard is then available at http://localhost:8000/. The `VOLVE_API_TOKEN` value must match `volve_agent_token` in `seid.conf`, because Vardlokk authenticates with it as a Bearer token.

The example configuration above points Vardlokk at `http://localhost:8000/api/v1/audits`, which is the direct uvicorn endpoint. If you mount Volve behind a reverse proxy at `/volve`, change that to `http://your-host/volve/api/v1/audits`.

## Safety Mechanism
Seid runs commands as the interactive user and requires human approval for each `run_local_command` invocation, including when `--unsafe` is used. Vardlokk is different: it runs unattended and is always read-only. Its BeeAI agent only receives fixed tools for host snapshots, allowlisted directory-usage scans, and read-only systemd/journal inspection. It has no arbitrary shell tool, and `--unsafe` is rejected. The systemd service should additionally use `ProtectSystem=strict`, `ProtectHome=read-only`, and `NoNewPrivileges=yes`; any future remote MCP tools must also use read-only credentials enforced by the remote service.

The Vardlokk prototype requires each finding to cite evidence IDs returned by its tools. It resolves those IDs to exact diagnostic output when building the existing Volve payload. Broad/destructive remediation commands are omitted from the payload and marked for administrator review.

Diagnostic output, including selected journal entries, is sent to the configured model endpoint. Use an endpoint approved for that host's data; this prototype does not provide comprehensive secret or personal-data redaction.

## License
This project is licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1). See the LICENSE file for details.
