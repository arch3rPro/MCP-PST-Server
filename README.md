<h1 align="center">MCP-PST-Server</h1>

<p align="center">
  <em>Windows AI-Assisted Penetration Testing MCP Server</em>
</p>

<p align="center">
  <a href="README-ZH.md"><strong>中文文档 </strong></a> | 
  <a href="README.md"><strong>English README</strong></a>
</p>

**PST MCP Server** is a lightweight API bridge designed to connect MCP Clients (e.g., Cherry Studio, Claude Desktop) to an API server, enabling command execution on a Windows terminal. This allows AI Agents or AI Clients to seamlessly invoke various penetration testing tools within the Windows environment, achieving **AI-assisted penetration testing**.

This enables AI to run terminal tools like `nmap`, `ehole`, and others, interact with web applications using tools like `curl`, `gobuster`, solve **CTF web challenges** in real-time, and assist in **solving machines from HTB or THM**.

## Directory Structure

- `pst_server.py`: Windows API Server (Endpoints: `/api/tools/<tool>`, `/api/command`, `/health`)
- `mcp_server.py`: MCP Client, encapsulates tools as MCP tools and forwards them to the API Server

---

## 🔍 Use Case

The goal is to enable AI-driven offensive security testing by:

- Letting the MCP interact with AI endpoints like OpenAI, Claude, DeepSeek, or any other models.
- Exposing an API to execute commands on a Windows machine.
- Using AI to suggest and run terminal commands to solve CTF challenges or automate penetration testing tasks.
- Allowing MCP apps to send custom requests (e.g., `curl`, `nmap`, `ehole`, etc.) and receive structured outputs.

---

## 🚀 Features

- 🧠 **AI Endpoint Integration**: Connect your Windows machine to any MCP of your liking such as Claude Desktop or Cherry-Studio.
- 🖥️ **Command Execution API**: Exposes a controlled API to execute terminal commands on your Windows machine.
- 🕸️ **Web Challenge Support**: AI can interact with websites and APIs, capture flags via `curl` and any other tool AI needs.
- 🔐 **Designed for Offensive Security Professionals**: Ideal for red teamers, bug bounty hunters, or CTF players automating common tasks.
- 📊 **Automated Wordlist Management**: Automatically generate and manage security testing wordlists (passwords, admin accounts, API endpoints).
- 🗂️ **Temporary File Management**: Automatic management of temporary files created during security testing.
- 📈 **Performance Monitoring**: Built-in performance monitoring and detailed logging for all operations.
- 🔄 **Error Handling & Retry Mechanisms**: Robust error handling with automatic retry capabilities.
- 🌐 **Multiple Transport Modes**: Support for stdio, SSE, and HTTP transport modes.
- 📚 **Comprehensive Documentation**: Detailed user guides, API references, and integration examples.

---

## 🛠️ Installation

### On Pentest-Windows Machine (Will act as PST Server)
```bash
git clone https://github.com/arch3rPro/MCP-PST-Server.git
cd MCP-PST-Server
pip install -r requirements.txt
python3 pst_server.py
```

### On your MCP Client (You can run on Windows or Linux)
- You will want to run `python3 /absolute/path/to/mcp_server.py http://WINDOWS_IP:5100`

#### Configuration for Claude Desktop:
Edit claude_desktop_config.json

```json
{
    "mcpServers": {
        "pst_mcp": {
            "command": "python3",
            "args": [
                "/absolute/path/to/mcp_server.py",
                "--server",
                "http://WINDOWS_IP:5100/"
            ]
        }
    }
}
```

#### Configuration for [Cherry Studio](https://github.com/CherryHQ/cherry-studio):
```json
{
    "mcpServers": {
        "PST-MCP": {
            "name": "pst_mcp",
            "type": "stdio",
            "isActive": true,
            "command": "python3",
            "args": [
                "/absolute/path/to/mcp_server.py",
                "--server",
                "http://localhost:5100"
            ]
        }
    }
}
```

## Installing Common Penetration Testing Tools (using Scoop and PST-Bucket)

1. Install Scoop: https://scoop.sh/
2. Add PST-Bucket:
   - `scoop bucket add ar https://github.com/arch3rPro/PST-Bucket`
3. Install tools (examples, streamline/expand as needed):
   - `scoop install nmap httpx ffuf feroxbuster fscan hydra hackbrowserdata`
   - `scoop install subfinder dnsx naabu nuclei katana bbot`
   - `scoop install masscan nikto gobuster john ehole`
   - `scoop install metasploit` (if not available, refer to official installer)
   - Optional: `pip install sqlmap`
   - Netcat: Use `ncat` (installed with `nmap`), or `nc` (optional)

> Recommendation: Use Pentest-Windows Environment Image (with many tools): https://github.com/arch3rPro/Pentest-Windows

## Starting the API Server

The PST API Server supports various command-line options for configuration:

### Command Line Options

```bash
python pst_server.py [options]
```

- `--host HOST`: Server host address (default: 0.0.0.0)
- `--port PORT`: Server port number (default: 5100)
- `--timeout SECONDS`: Command execution timeout in seconds (default: 180)
- `--debug`: Enable debug mode for detailed logging

### Starting the API Server with custom options

- Navigate to directory: `/absolute/path/to/MCP-PST-Server`
- Start with default settings:
  - `python pst_server.py`
- Start with custom settings:
  - `python pst_server.py --host 0.0.0.0 --port 5100 --timeout 300 --debug`
- Health Check (PowerShell):
  - `Invoke-RestMethod -Uri http://localhost:5100/health -Method GET`

## Starting the MCP Server with custom options

The MCP Server supports multiple transport modes and can be configured with various parameters:

### Transport Modes

1. **STDIO Mode (Default)**: Standard input/output communication, ideal for most MCP clients like Claude Desktop
2. **SSE Mode**: Server-Sent Events transport, useful for web-based clients
3. **HTTP Mode**: Direct HTTP API access, suitable for custom integrations

### Command Line Options

```bash
python mcp_server.py [options]
```

- `--server URL`: PST API server URL (default: http://localhost:5100)
- `--timeout SECONDS`: Request timeout in seconds (default: 300)
- `--host HOST`: MCP server host (default: 127.0.0.1)
- `--port PORT`: MCP server port (default: 8000)
- `--path PATH`: MCP server access path for stdio mode (default: /mcp)
- `--transport MODE`: Transport mode - studio (stdio), sse, or http (default: studio)
- `--debug`: Enable debug logging

### Starting the MCP Server

- **STDIO Mode (Default)**:
  ```bash
  python3 mcp_server.py --server http://localhost:5100 --debug
  ```

- **SSE Mode**:
  ```bash
  python3 mcp_server.py --server http://localhost:5100 --transport sse --host 0.0.0.0 --port 8000 --path /sse
  ```

- **HTTP Mode**:
  ```bash
  python3 mcp_server.py --server http://localhost:5100 --transport http --host 0.0.0.0 --port 8000 --path /mcp
  ```

### Configuration for Custom Integrations (HTTP Mode):

- Nmap:
  ```powershell
  $body = @{ target="scanme.nmap.org"; scan_type="-sV"; ports=""; additional_args="-T4 -Pn" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/nmap -Method POST -Body $body -ContentType "application/json"
  ```

- FFUF:
  ```powershell
  $body = @{ url="http://target"; wordlist="C:\wordlists\common.txt"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/ffuf -Method POST -Body $body -ContentType "application/json"
  ```

- ProjectDiscovery:
  ```powershell
  # Subfinder
  $body = @{ domain="example.com"; list_file=""; additional_args="-all -silent" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/subfinder -Method POST -Body $body -ContentType "application/json"

  # DNSX
  $body = @{ domain="example.com"; list_file=""; additional_args="-a -resp -silent" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/dnsx -Method POST -Body $body -ContentType "application/json"

  # Naabu
  $body = @{ host="example.com"; list_file=""; ports=""; additional_args="-silent" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/naabu -Method POST -Body $body -ContentType "application/json"

  # Nuclei
  $body = @{ target="http://example.com"; list_file=""; template=""; tags=""; severity=""; additional_args="-silent" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/nuclei -Method POST -Body $body -ContentType "application/json"

  # Katana
  $body = @{ url="http://example.com"; list_file=""; depth="3"; additional_args="-silent" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/katana -Method POST -Body $body -ContentType "application/json"
  ```

- Afrog:
  ```powershell
  $body = @{ target="http://example.com"; list_file=""; pocs=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/afrog -Method POST -Body $body -ContentType "application/json"
  ```

- Ehole (Fingerprinting):
  ```powershell
  $body = @{ target="http://example.com"; list_file=""; fingerprints=""; output=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/ehole -Method POST -Body $body -ContentType "application/json"
  ```

- Nikto:
  ```powershell
  $body = @{ target="http://example.com"; port=""; ssl=$false; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/nikto -Method POST -Body $body -ContentType "application/json"
  ```

- Gobuster (Directory Mode):
  ```powershell
  $body = @{ mode="dir"; url="http://example.com"; wordlist="C:\wordlists\common.txt"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/gobuster -Method POST -Body $body -ContentType "application/json"
  ```

- Masscan:
  ```powershell
  $body = @{ target="192.168.1.0/24"; ports="80,443"; rate="1000"; iface=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/masscan -Method POST -Body $body -ContentType "application/json"
  ```

- John (Cracking Example):
  ```powershell
  $body = @{ hash_file="C:\hashes\passwd.txt"; wordlist="C:\wordlists\rockyou.txt"; format=""; mask=""; rules=$false; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/john -Method POST -Body $body -ContentType "application/json"
  ```

- Metasploit (msfconsole -x):
  ```powershell
  $body = @{ msf_cmd="version; exit"; rc_file=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/metasploit -Method POST -Body $body -ContentType "application/json"
  ```

- Netcat:
  ```powershell
  # Listen
  $body = @{ mode="listen"; listen_port="4444"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/netcat -Method POST -Body $body -ContentType "application/json"
  # Connect
  $body = @{ mode="client"; host="127.0.0.1"; port="4444"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/netcat -Method POST -Body $body -ContentType "application/json"
  ```

- BBOT (Recursive Internet Scanner):
  ```powershell
  # Using preset
  $body = @{ target="example.com"; preset="web-basic"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/bbot -Method POST -Body $body -ContentType "application/json"
  
  # Using specific modules
  $body = @{ target="example.com"; modules="subfinder-enum,dnsx-resolve,nmap-portscan"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/bbot -Method POST -Body $body -ContentType "application/json"
  
  # With output directory
  $body = @{ target="example.com"; preset="cloud-enum"; output_dir="C:\bbot_output"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/bbot -Method POST -Body $body -ContentType "application/json"
  ```

- General Command:
  ```powershell
  $body = @{ command="whoami" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/command -Method POST -Body $body -ContentType "application/json"
  ```

## Security Notes

- Use all tools and features only within legally authorized scopes.
- All command parameters are passed directly to the underlying tools; exercise caution with input to avoid injection and unintended operations.
- Execution timeout defaults to 180s and can be adjusted via `--timeout` at startup.

## Iteration Plan

- Add more endpoints based on the tool list in PST-Bucket (e.g., `afrog`, `ehole`, `fscan`, etc.).
- Enhance parameter validation and output parsing for each tool to improve stability and readability.
- Implement advanced workflow orchestration for complex security testing scenarios.
- Add support for custom tool definitions and user-defined workflows.
- Develop web-based management interface for monitoring and configuration.

## ⚠️ Disclaimer:
This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.
The author assumes no responsibility for misuse.