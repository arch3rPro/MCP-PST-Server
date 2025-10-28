# MCP-PST-Server (Windows AI 辅助渗透测试环境)

**语言:** [English](README.md) | [中文](README-ZH.md)

**PST MCP 服务器**是一个轻量级的 API 网桥，旨在将 MCP 客户端（例如：Cherry Studio, Claude Desktop）与 API 服务器连接起来，从而在 Windows 终端上执行命令。通过这种方式，AI Agent 或 AI 客户端能够无缝地调用 Windows 环境中的各种渗透测试工具，实现 **AI 辅助渗透测试**。

这使得 AI 能够运行 `nmap`、`ehole` 等终端工具，通过 `curl`、`gobuster` 等工具与 Web 应用程序交互，实时解决 **CTF Web 挑战**，并协助解决 **HTB 或 THM 机器**。

## 目录结构

- `pst_server.py`：Windows API 服务端（端点：`/api/tools/<tool>`, `/api/command`, `/health`）
- `mcp_server.py`：MCP 客户端，封装工具为 MCP 工具并转发至 API Server

---

## 🔍 使用案例

目标是通过以下方式实现 AI 驱动的网络安全测试：

- 让 MCP 与 OpenAI、Claude、DeepSeek 或任何其他模型等 AI 端点进行交互。
- 暴露一个 API，用于在 Windows 机器上执行命令。
- 使用 AI 建议并运行终端命令来解决 CTF 挑战或自动化渗透测试任务。
- 允许 MCP 应用程序发送自定义请求（例如 `curl`、`nmap`、`ehole` 等）并接收结构化输出。

---

## 🚀 功能

- 🧠 **AI 端点集成**：将您的 Windows 机器连接到您喜欢的任何 MCP，例如 Claude Desktop 或 Cherry-Studio。
- 🖥️ **命令执行 API**：暴露一个受控 API，用于在您的 Windows 机器上执行终端命令。
- 🕸️ **Web 挑战支持**：AI 可以与网站和 API 交互，通过 `curl` 和 AI 所需的任何其他工具捕获标志。
- 🔐 **专为攻击性安全专业人员设计**：非常适合红队成员、漏洞赏金猎人或 CTF 玩家自动化常见任务。

---

## 🛠️ 安装

### Pentest-Windows 机器上（将作为 PST 服务器）
```bash
git clone https://github.com/arch3rPro/MCP-PST-Server.git
cd MCP-PST-Server
pip install -r requirements.txt
python3 pst_server.py
```

### MCP 客户端上（您可以在 Windows 或 Linux 上运行）
- 您需要运行 `python /absolute/path/to/mcp_server.py http://WINDOWS_IP:5100`

#### Claude Desktop 配置：
编辑 claude_desktop_config.json

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

#### [Cherry Studio](https://github.com/CherryHQ/cherry-studio) 配置：
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


## 安装常用渗透工具（使用 Scoop 与 PST-Bucket）

1. 安装 Scoop：https://scoop.sh/
2. 添加 PST-Bucket：
   - `scoop bucket add ar https://github.com/arch3rPro/PST-Bucket`
3. 安装工具（示例，按需精简/扩展）：
   - `scoop install nmap httpx ffuf feroxbuster fscan hydra hackbrowserdata`
   - `scoop install subfinder dnsx naabu nuclei katana`
   - `scoop install masscan nikto gobuster john ehole`
   - `scoop install metasploit`（如不可用，参考官方安装包）
   - 可选：`pip install sqlmap`
   - Netcat：使用 `ncat`（随 `nmap` 安装），或 `nc`（可选）

> 推荐：直接使用Pentest-Windows 环境镜像（含大量工具）：https://github.com/arch3rPro/Pentest-Windows

## 启动 API 服务器

- 进入目录：`/absolute/path/to/MCP-PST-Server`
- 启动：
  - `python pst_server.py --debug --port 5100`
- 健康检查（PowerShell）：
  - `Invoke-RestMethod -Uri http://localhost:5100/health -Method GET`

## 启动 MCP 客户端

- 启动 MCP：
  - `python mcp_server.py --server http://localhost:5100 --debug`

## 示例调用（API 服务器）

- Nmap：
  ```powershell
  $body = @{ target="scanme.nmap.org"; scan_type="-sV"; ports=""; additional_args="-T4 -Pn" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/nmap -Method POST -Body $body -ContentType "application/json"
  ```

- FFUF：
  ```powershell
  $body = @{ url="http://target"; wordlist="C:\wordlists\common.txt"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/ffuf -Method POST -Body $body -ContentType "application/json"
  ```

- ProjectDiscovery：
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

- Afrog：
  ```powershell
  $body = @{ target="http://example.com"; list_file=""; pocs=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/afrog -Method POST -Body $body -ContentType "application/json"
  ```

- Ehole（指纹识别）：
  ```powershell
  $body = @{ target="http://example.com"; list_file=""; fingerprints=""; output=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/ehole -Method POST -Body $body -ContentType "application/json"
  ```

- Nikto：
  ```powershell
  $body = @{ target="http://example.com"; port=""; ssl=$false; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/nikto -Method POST -Body $body -ContentType "application/json"
  ```

- Gobuster（目录模式）：
  ```powershell
  $body = @{ mode="dir"; url="http://example.com"; wordlist="C:\wordlists\common.txt"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/gobuster -Method POST -Body $body -ContentType "application/json"
  ```

- Masscan：
  ```powershell
  $body = @{ target="192.168.1.0/24"; ports="80,443"; rate="1000"; iface=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/masscan -Method POST -Body $body -ContentType "application/json"
  ```

- John（破解示例）：
  ```powershell
  $body = @{ hash_file="C:\hashes\passwd.txt"; wordlist="C:\wordlists\rockyou.txt"; format=""; mask=""; rules=$false; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/john -Method POST -Body $body -ContentType "application/json"
  ```

- Metasploit（msfconsole -x）：
  ```powershell
  $body = @{ msf_cmd="version; exit"; rc_file=""; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/metasploit -Method POST -Body $body -ContentType "application/json"
  ```

- Netcat：
  ```powershell
  # 监听
  $body = @{ mode="listen"; listen_port="4444"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/netcat -Method POST -Body $body -ContentType "application/json"
  # 连接
  $body = @{ mode="client"; host="127.0.0.1"; port="4444"; additional_args="" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/tools/netcat -Method POST -Body $body -ContentType "application/json"
  ```

- 通用命令：
  ```powershell
  $body = @{ command="whoami" } | ConvertTo-Json
  Invoke-RestMethod -Uri http://localhost:5100/api/command -Method POST -Body $body -ContentType "application/json"
  ```

## 安全说明

- 仅在合法授权范围内使用所有工具与功能。
- 所有命令参数均直接传入底层工具，请谨慎控制输入，避免注入与误操作。
- 执行超时默认 180s，在启动时通过 `--timeout` 可调整。

## 迭代计划

- 根据 PST-Bucket 中的工具清单添加更多端点（例如 `afrog`, `ehole`, `fscan` 等）。
- 为各工具增加参数校验与输出解析，提高稳定性与可读性。

## ⚠️ 免责声明：
本项目仅用于教育和道德测试目的。严禁滥用所提供的信息或工具——包括未经授权的访问、利用或恶意活动——是严格禁止的。
作者对滥用不承担任何责任。