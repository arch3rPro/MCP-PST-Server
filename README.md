# MCP-PST-Server (Windows AI-Assisted Penetration Testing Environment)

**Language:** [English](README.md) | [中文](README-ZH.md)

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
- You will want to run `python /absolute/path/to/mcp_server.py http://WINDOWS_IP:5100`

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
   - `scoop install subfinder dnsx naabu nuclei katana`
   - `scoop install masscan nikto gobuster john ehole`
   - `scoop install metasploit` (if not available, refer to official installer)
   - Optional: `pip install sqlmap`
   - Netcat: Use `ncat` (installed with `nmap`), or `nc` (optional)

> Recommendation: Use Pentest-Windows Environment Image (with many tools): https://github.com/arch3rPro/Pentest-Windows

## Starting the API Server

- Navigate to directory: `/absolute/path/to/MCP-PST-Server`
- Start:
  - `python pst_server.py --debug --port 5100`
- Health Check (PowerShell):
  - `Invoke-RestMethod -Uri http://localhost:5100/health -Method GET`

## Starting the MCP Client

- Start MCP:
  - `python mcp_server.py --server http://localhost:5100 --debug`

## Example API Calls (API Server)

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

## ⚠️ Disclaimer:
This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.
The author assumes no responsibility for misuse.