# Seid

**Seid** (pronounced *said*) is a command-line AI system administrator tool designed to help you manage your Linux environment safely and efficiently. 

While **Seid** serves as your primary, interactive AI assistant in the terminal, the ecosystem also includes **Vardlokk** (an automated system auditor) and **Volve** (a centralized dashboard) for fleet-wide monitoring and remediation.

## Inspiration
The name **Seid** is derived from *seiðr*, an Old Norse practice of magic involving prophecy, trance states, and the manipulation of fate. Just as seiðr practitioners navigated unseen forces to alter reality, Seid helps system administrators navigate complex technical landscapes with foresight, precision, and control.

The extended toolset follows this mythological framework:
*   **Vardlokk:** Named after the ritual song used to draw in spirits and hidden knowledge. In our ecosystem, Vardlokk runs in the background on your servers, gathering telemetry, checking package versions, and analyzing vulnerabilities.
*   **Volve:** Named after the seeress who interpreted the visions. Volve acts as the central GUI/Dashboard that receives Vardlokk's findings, presenting you with the big picture and actionable remediation steps.

## Architecture Overview
*   **Seid (Core CLI):** Your interactive, local AI sysadmin. Ask it to troubleshoot issues, read logs, or configure services directly from your terminal.
*   **Vardlokk (Automated Agent):** A background daemon utilizing the Seid toolchain to perform scheduled, autonomous system audits (e.g., security, performance) and generate structured JSON reports.
*   **Volve (Dashboard API):** The central receiver for Vardlokk reports, allowing administrators to review findings and approve remediation commands across a fleet of servers.

## Features
- 🛡 **Safe by Default**: Runs in strictly read-only mode to prevent accidental system mutations.
- 🔓 **Controlled Mutations**: Use the `--unsafe` flag to allow Seid or Vardlokk to execute commands that modify system state.
- 🤖 **AI-Powered**: Leverages local LLMs (via Ollama or compatible APIs) and `smolagents` for intelligent command execution.
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
python -m venv venv
. venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
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

Larger models generally reason better, but check `ollama ps` after the first request. If the `PROCESSOR` column is not 100% GPU, part of the model is running on CPU and each agent step can take tens of seconds. That is tolerable for a short Seid question, but painful for a Vardlokk audit that may run up to 40 steps.

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
By default, the toolchain blocks potentially dangerous mutating actions (e.g., rm, dnf install, systemctl stop). It will return a clear message explaining the block and instruct you to use --unsafe if you wish to proceed. When running in safe mode, commands are executed as your own user through `systemd-run --user` with a read-only system view. Even when running in --unsafe mode, interactive prompts ensure a human administrator approves every mutating command before execution.

## License
This project is licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1). See the LICENSE file for details.
