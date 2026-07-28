"""
seid_tools.documentation: External Knowledge Retrieval

Provides tools for the agent to look up local manual pages and search 
official OS documentation online. These tools help ground the LLM's 
answers in factual, system-specific documentation, reducing hallucinations.
"""

import re
import subprocess
import urllib.request

from ddgs import DDGS
from smolagents import tool

# Known phrases returned by Cloudflare or Web Application Firewalls (WAF) 
# when our scraping attempts are blocked.
BOT_PHRASES = [
    "Making sure you're not a bot", 
    "Anubis is a compromise", 
    "Cloudflare", 
    "Enable JavaScript and cookies",
    "Attention Required!"
]

# Safeguards for the LLM's context window
MAX_MAN_LENGTH = 9000
MAX_DOC_LENGTH = 8000


@tool
def search_local_man_pages(query: str) -> str:
    """Searches the system's local manual pages to find documentation on tools, flags, and syntax.
    
    Args:
        query: The tool or command you want to read the manual for (e.g., 'dnf', 'rsync', 'firewalld').
    """
    # SECURITY CONTEXT: Sanitize the query to prevent command injection.
    # Because we use a shell pipeline below, we must strictly validate the input 
    # to ensure the LLM (or a prompt injection attack) cannot append arbitrary commands.
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", query):
        return f"Error: Invalid manual page name '{query}'. Only alphanumeric characters, dashes, and underscores are allowed."

    try:
        # We pipe the output through `col -bx` to strip backspaces and terminal 
        # formatting characters that `man` generates. These control characters 
        # often confuse LLM tokenizers.
        cmd = f"man {query} | col -bx"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        
        if not result.stdout:
            return f"Could not find any local manual for '{query}'."
            
        output = result.stdout.strip()
        
        if len(output) > MAX_MAN_LENGTH:
            return output[:MAX_MAN_LENGTH] + "\n\n... [MANUAL TRUNCATED DUE TO LENGTH]"
            
        return output
        
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out while fetching manual for '{query}'."
    except Exception as e:
        return f"Error reading man pages: {str(e)}"


@tool
def search_os_documentation(query: str, os_name: str = "linux") -> str:
    """Searches official documentation sites prioritized by OS family, with an Arch Wiki fallback.
    
    Args:
        query: The technical problem or tool you are trying to configure.
        os_name: The operating system (e.g., 'fedora', 'rhel', 'ubuntu', 'arch').
    """
    os_lower = os_name.lower()
    search_strategies = []
    
    # 1. Build prioritized search queries targeting official documentation
    if os_lower in ['fedora', 'centos', 'rhel', 'rocky', 'openshift', 'okd']:
        search_strategies.append(f"{query} site:docs.fedoraproject.org")
        search_strategies.append(f"{query} site:access.redhat.com/documentation")
    elif os_lower in ['ubuntu']:
        search_strategies.append(f"{query} site:ubuntu.com/server/docs")
    elif os_lower in ['debian']:
        search_strategies.append(f"{query} site:wiki.debian.org")
        
    # 2. Fallbacks: The Arch Wiki is excellent for general Linux troubleshooting
    search_strategies.append(f"{query} site:wiki.archlinux.org")
    search_strategies.append(f"{query} {os_lower} documentation")

    top_url = None
    snippet = ""
    
    # 3. Perform the search and grab the top result
    for search_query in search_strategies:
        try:
            results = DDGS().text(search_query, max_results=1)
            if results:
                top_url = results[0]['href']
                snippet = results[0].get('body', 'No snippet available.')
                break
        except Exception:
            continue
            
    if not top_url:
        return "No documentation found for this query."
        
    # 4. Fetch the content using Jina Reader (r.jina.ai)
    # Jina strips raw HTML and returns clean, LLM-friendly Markdown.
    try:
        jina_url = f"https://r.jina.ai/{top_url}"
        req = urllib.request.Request(jina_url, headers={'User-Agent': 'Mozilla/5.0 Seidr/1.0'})
        
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            
        # WAF Check: If Jina got blocked by Cloudflare/anti-bot, fall back to the search snippet
        if any(phrase in content for phrase in BOT_PHRASES):
            return f"Blocked by anti-bot shield at {top_url}.\n\nSearch snippet fallback:\n{snippet}"
            
        if len(content) > MAX_DOC_LENGTH:
            content = content[:MAX_DOC_LENGTH] + "\n\n... [CONTENT TRUNCATED DUE TO LENGTH]"
            
        return f"Docs from {top_url}:\n\n{content}"
        
    except Exception as e:
        return f"Failed to read full page ({str(e)}).\n\nSearch snippet fallback:\n{snippet}"