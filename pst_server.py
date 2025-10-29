import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import shutil
import tempfile
from typing import Dict, List, Optional, Any

import requests
from flask import Flask, jsonify, request

class CommandExecutor:
    def __init__(self, timeout: int = 180):
        self.timeout = timeout

    def run(self, cmd: List[str]) -> Dict[str, str]:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                text=True,
            )
            timer = threading.Timer(self.timeout, self._kill_process, args=(proc,))
            timer.start()
            stdout, stderr = proc.communicate()
            timer.cancel()
            return {
                "ok": proc.returncode == 0,
                "returncode": str(proc.returncode),
                "stdout": stdout or "",
                "stderr": stderr or "",
            }
        except FileNotFoundError as e:
            return {"ok": False, "returncode": "127", "stdout": "", "stderr": f"Executable not found: {e}"}
        except Exception as e:
            return {"ok": False, "returncode": "1", "stdout": "", "stderr": f"Error running command: {e}"}

    def _kill_process(self, proc: subprocess.Popen):
        try:
            proc.kill()
        except Exception:
            pass

def supported_tools() -> List[str]:
    return [
        "nmap", "httpx", "ffuf", "feroxbuster", "fscan", "hydra", "hackbrowserdata",
        "subfinder", "dnsx", "naabu", "nuclei", "katana", "afrog", "sqlmap",
        "metasploit", "john", "nikto", "gobuster", "masscan", "netcat", "ehole", "bbot",
    ]

ESSENTIAL_TOOLS = ["nmap", "httpx", "subfinder", "dnsx", "naabu", "nuclei", "ffuf", "feroxbuster", "fscan", "hydra"]

def add_args(args: List[str], additional: str) -> List[str]:
    if additional:
        args.extend(shlex.split(additional))
    return args

def build_command(tool: str, data: Dict[str, str]) -> List[str]:
    tool = tool.lower()

    if tool == "nmap":
        target = data.get("target", "")
        scan_type = data.get("scan_type", "-sV")
        ports = data.get("ports", "")
        timing = data.get("timing", "T4")
        ping_scan = data.get("ping_scan", "-Pn")
        os_detection = data.get("os_detection", "")
        service_detection = data.get("service_detection", "")
        script_scan = data.get("script_scan", "")
        script_args = data.get("script_args", "")
        output_format = data.get("output_format", "")
        output_file = data.get("output_file", "")
        min_rate = data.get("min_rate", "")
        max_rate = data.get("max_rate", "")
        
        cmd = ["nmap"]
        
        # 添加扫描类型
        if scan_type:
            cmd += [scan_type]
            
        # 添加时序模板
        if timing:
            cmd += [f"-{timing}"]
            
        # 添加ping扫描选项
        if ping_scan:
            cmd += [ping_scan]
            
        # 添加操作系统检测
        if os_detection:
            cmd += [os_detection]
            
        # 添加服务检测
        if service_detection:
            cmd += [service_detection]
            
        # 添加脚本扫描
        if script_scan:
            cmd += ["--script", script_scan]
            
        # 添加脚本参数
        if script_args:
            cmd += ["--script-args", script_args]
            
        # 添加端口范围
        if ports:
            cmd += ["-p", ports]
            
        # 添加输出格式和文件
        if output_format and output_file:
            cmd += [f"{output_format}", output_file]
        elif output_format:
            cmd += [output_format]
            
        # 添加发包速率限制
        if min_rate:
            cmd += ["--min-rate", min_rate]
        if max_rate:
            cmd += ["--max-rate", max_rate]
            
        # 添加目标
        if target:
            cmd += [target]
            
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "httpx":
        target = data.get("target", "")
        list_file = data.get("list_file", "")
        cmd = ["httpx"]
        if list_file:
            cmd += ["-l", list_file]
        elif target:
            cmd += ["-u", target]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "ffuf":
        url = data.get("url", "")
        wordlist = data.get("wordlist", "")
        cmd = ["ffuf", "-u", url]
        if wordlist:
            cmd += ["-w", wordlist]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "feroxbuster":
        url = data.get("url", "")
        wordlist = data.get("wordlist", "")
        cmd = ["feroxbuster", "-u", url]
        if wordlist:
            cmd += ["-w", wordlist]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "fscan":
        target = data.get("target", "")
        cmd = ["fscan", "-h", target]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "hydra":
        target = data.get("target", "")
        service = data.get("service", "ssh")
        username = data.get("username", "")
        username_file = data.get("username_file", "")
        password = data.get("password", "")
        password_file = data.get("password_file", "")
        cmd = ["hydra"]
        if username_file:
            cmd += ["-L", username_file]
        elif username:
            cmd += ["-l", username]
        if password_file:
            cmd += ["-P", password_file]
        elif password:
            cmd += ["-p", password]
        if target:
            cmd += [f"{service}://{target}"]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "hackbrowserdata":
        output_dir = data.get("output_dir", os.getcwd())
        browser = data.get("browser", "")
        cmd = ["hackbrowserdata", "-o", output_dir, "-f"]
        if browser:
            cmd += ["-b", browser]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "subfinder":
        domain = data.get("domain", "")
        list_file = data.get("list_file", "")
        cmd = ["subfinder", "-silent"]
        if list_file:
            cmd += ["-dL", list_file]
        elif domain:
            cmd += ["-d", domain]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "dnsx":
        domain = data.get("domain", "")
        list_file = data.get("list_file", "")
        cmd = ["dnsx", "-silent"]
        if list_file:
            cmd += ["-l", list_file]
        elif domain:
            cmd += ["-d", domain]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "naabu":
        host = data.get("host", "")
        list_file = data.get("list_file", "")
        ports = data.get("ports", "")
        cmd = ["naabu", "-silent"]
        if list_file:
            cmd += ["-l", list_file]
        elif host:
            cmd += ["-host", host]
        if ports:
            cmd += ["-p", ports]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "nuclei":
        target = data.get("target", "")
        list_file = data.get("list_file", "")
        template = data.get("template", "")
        tags = data.get("tags", "")
        severity = data.get("severity", "")
        cmd = ["nuclei", "-silent"]
        if list_file:
            cmd += ["-l", list_file]
        elif target:
            cmd += ["-u", target]
        if template:
            cmd += ["-t", template]
        if tags:
            cmd += ["-tags", tags]
        if severity:
            cmd += ["-severity", severity]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "katana":
        url = data.get("url", "")
        list_file = data.get("list_file", "")
        depth = str(data.get("depth", "3"))
        cmd = ["katana", "-silent", "-depth", depth]
        if list_file:
            cmd += ["-list", list_file]
        elif url:
            cmd += ["-u", url]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "afrog":
        target = data.get("target", "")
        list_file = data.get("list_file", "")
        pocs = data.get("pocs", "")
        cmd = ["afrog"]
        if list_file:
            cmd += ["-T", list_file]
        elif target:
            cmd += ["-t", target]
        if pocs:
            cmd += ["-P", pocs]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "sqlmap":
        url = data.get("url", "")
        post_data = data.get("data", "")
        cmd = [sys.executable, "-m", "sqlmap", "-u", url, "--batch"]
        if post_data:
            cmd += ["--data", post_data]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "ehole":
        target = data.get("target", "")
        list_file = data.get("list_file", "")
        fingerprints = data.get("fingerprints", "")
        output = data.get("output", "")
        eh_bin = "EHole" if shutil_which("EHole") else ("ehole" if shutil_which("ehole") else "EHole")
        cmd = [eh_bin]
        if list_file:
            cmd += ["-l", list_file]
        elif target:
            cmd += ["-u", target]
        if fingerprints:
            cmd += ["-f", fingerprints]
        if output:
            cmd += ["-o", output]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "metasploit":
        msf_cmd = data.get("msf_cmd", "")
        rc_file = data.get("rc_file", "")
        
        if not rc_file and msf_cmd:
            # Create a temporary resource file
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".rc") as temp_rc_file:
                temp_rc_file.write(msf_cmd)
                rc_file = temp_rc_file.name
            # Add a cleanup task for the temporary file
            data["_temp_rc_file"] = rc_file

        cmd = ["D:\\Global\\apps\\metasploit-framework\\current\\bin\\msfconsole.bat", "-q"]
        if rc_file:
            cmd += ["-r", rc_file]
        else:
            cmd += ["-x", "version; exit"]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "john":
        hash_file = data.get("hash_file", "")
        wordlist = data.get("wordlist", "")
        fmt = data.get("format", "")
        mask = data.get("mask", "")
        rules = data.get("rules", "")
        cmd = ["john"]
        if wordlist:
            cmd += [f"--wordlist={wordlist}"]
        if fmt:
            cmd += [f"--format={fmt}"]
        if rules:
            cmd += ["--rules"]
        if mask:
            cmd += [f"--mask={mask}"]
        if hash_file:
            cmd += [hash_file]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "nikto":
        target = data.get("target", "")
        port = data.get("port", "")
        ssl = str(data.get("ssl", "")).lower() in {"true", "1", "yes"}
        cmd = ["nikto"]
        if target:
            cmd += ["-host", target]
        if port:
            cmd += ["-port", port]
        if ssl:
            cmd += ["-ssl"]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "gobuster":
        mode = data.get("mode", "dir")
        cmd = ["gobuster", mode]
        if mode == "dir":
            url = data.get("url", "")
            wordlist = data.get("wordlist", "")
            if url:
                cmd += ["-u", url]
            if wordlist:
                cmd += ["-w", wordlist]
        elif mode == "dns":
            domain = data.get("domain", "")
            wordlist = data.get("wordlist", "")
            if domain:
                cmd += ["-d", domain]
            if wordlist:
                cmd += ["-w", wordlist]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "masscan":
        target = data.get("target", "")
        ports = data.get("ports", "")
        rate = data.get("rate", "")
        iface = data.get("iface", "")
        cmd = ["masscan"]
        if target:
            cmd += [target]
        if ports:
            cmd += ["-p", ports]
        if rate:
            cmd += ["--rate", rate]
        if iface:
            cmd += ["-e", iface]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "netcat":
        host = data.get("host", "")
        port = str(data.get("port", ""))
        mode = data.get("mode", "client")
        listen_port = str(data.get("listen_port", ""))
        binary = data.get("binary", "")
        # pick ncat or nc
        nc_bin = binary or ("ncat" if shutil_which("ncat") else ("nc" if shutil_which("nc") else "ncat"))
        cmd = [nc_bin]
        if mode == "listen":
            p = listen_port or port
            if p:
                cmd += ["-l", "-p", p, "-v", "-n"]
            else:
                cmd += ["-l", "-v", "-n"]
        else:
            if host and port:
                cmd += [host, port]
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "bbot":
        target = data.get("target", "")
        preset = data.get("preset", "")
        modules = data.get("modules", "")
        flags = data.get("flags", "")
        output_modules = data.get("output_modules", "")
        output_dir = data.get("output_dir", "")
        whitelist = data.get("whitelist", "")
        blacklist = data.get("blacklist", "")
        
        cmd = ["bbot"]
        
        # Add target(s)
        if target:
            cmd += ["-t", target]
        
        # Add preset(s)
        if preset:
            cmd += ["-p", preset]
        
        # Add module(s)
        if modules:
            cmd += ["-m", modules]
        
        # Add flags
        if flags:
            cmd += ["-f", flags]
        
        # Add output module(s)
        if output_modules:
            cmd += ["-om", output_modules]
        
        # Add output directory
        if output_dir:
            cmd += ["-o", output_dir]
        
        # Add whitelist
        if whitelist:
            cmd += ["-w", whitelist]
        
        # Add blacklist
        if blacklist:
            cmd += ["-b", blacklist]
        
        return add_args(cmd, data.get("additional_args", ""))

    raise ValueError(f"Unsupported tool: {tool}")

def shutil_which(name: str) -> Optional[str]:
    from shutil import which
    return which(name)

ALIAS_BINARIES = {
    "metasploit": ["msfconsole"],
    "netcat": ["ncat", "nc"],
    "ehole": ["EHole", "ehole"],
}

def tools_status_map(names: List[str]) -> Dict[str, bool]:
    status: Dict[str, bool] = {}
    for name in names:
        binaries = ALIAS_BINARIES.get(name, [name])
        ok = any(shutil_which(b) is not None for b in binaries)
        status[name] = ok
    return status

def validate_tool_params(tool: str, data: Dict[str, Any]) -> Optional[str]:
    # Basic parameter validation per tool to improve stability
    if tool == "ehole":
        target = str(data.get("target", "")).strip()
        list_file = str(data.get("list_file", "")).strip()
        fingerprints = str(data.get("fingerprints", "")).strip()
        if not target and not list_file:
            return "ehole 需要提供 'target' 或 'list_file' 之一"
        if list_file and not os.path.exists(list_file):
            return f"列表文件不存在: {list_file}"
        if fingerprints and not os.path.exists(fingerprints):
            return f"指纹文件不存在: {fingerprints}"
    
    if tool == "bbot":
        target = str(data.get("target", "")).strip()
        preset = str(data.get("preset", "")).strip()
        modules = str(data.get("modules", "")).strip()
        flags = str(data.get("flags", "")).strip()
        
        # BBOT requires at least one of target, preset, modules, or flags
        if not any([target, preset, modules, flags]):
            return "bbot 需要提供 'target', 'preset', 'modules', 或 'flags' 之一"
    
    return None

def parse_tool_output(tool: str, stdout: str, stderr: str) -> Dict[str, Any]:
    # Lightweight output parsing to aid readability; designed to be resilient
    lines = (stdout or "").splitlines()
    parsed: Dict[str, Any] = {"lines": lines}
    if tool == "ehole":
        urls = []
        for m in re.finditer(r"https?://[^\s]+", stdout or ""):
            urls.append(m.group(0))
        # Extract simple finding lines containing keyword patterns
        findings = [ln for ln in lines if re.search(r"(?i)(fingerprint|match|title|status)", ln)]
        parsed.update({"urls": urls, "findings": findings})
    elif tool == "bbot":
        # Extract URLs
        urls = []
        for m in re.finditer(r"https?://[^\s]+", stdout or ""):
            urls.append(m.group(0))
        
        # Extract subdomains
        subdomains = []
        for m in re.finditer(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", stdout or "", re.MULTILINE):
            subdomains.append(m.group(0))
        
        # Extract IP addresses
        ips = []
        for m in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", stdout or ""):
            ips.append(m.group(0))
        
        # Extract ports
        ports = []
        for m in re.finditer(r":(\d{1,5})\b", stdout or ""):
            port = int(m.group(1))
            if 1 <= port <= 65535 and port not in ports:
                ports.append(port)
        
        # Extract vulnerability findings
        vulnerabilities = [ln for ln in lines if re.search(r"(?i)(vulnerability|cve|vuln|rce|xss|sqli|lfi)", ln)]
        
        # Extract email addresses
        emails = []
        for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", stdout or ""):
            emails.append(m.group(0))
        
        parsed.update({
            "urls": urls,
            "subdomains": subdomains,
            "ips": ips,
            "ports": sorted(ports),
            "vulnerabilities": vulnerabilities,
            "emails": emails
        })
    return parsed

def fetch_pentest_windows_readme(branch: str = "main") -> str:
    url = f"https://raw.githubusercontent.com/arch3rPro/Pentest-Windows/{branch}/README.md"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception:
        return ""

def parse_tools_from_readme(md_text: str) -> List[str]:
    tools: List[str] = []
    for m in re.finditer(r"scoop\\s+install\\s+([^\\n\\r]+)", md_text, flags=re.IGNORECASE):
        tail = m.group(1).replace("`", " ")
        candidates = [t.strip() for t in tail.split() if t.strip()]
        flags = {"-g", "-y", "--global", "/S"}
        for c in candidates:
            if c.startswith("-") or c in flags:
                continue
            if re.match(r"^[A-Za-z0-9_-]{2,}$", c):
                tools.append(c)
    for m in re.finditer(r"^[\\-*]\\s*([A-Za-z0-9_-]{2,})\\s*$", md_text, flags=re.MULTILINE):
        tools.append(m.group(1))
    seen, uniq = set(), []
    for t in tools:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq

def create_app(executor: CommandExecutor) -> Flask:
    app = Flask(__name__)

    @app.route("/api/command", methods=["POST"])
    def api_command():
        data = request.get_json(force=True) or {}
        command = data.get("command")
        if not command:
            return jsonify({"ok": False, "error": "Missing 'command'"}), 400
        cmd = shlex.split(command)
        result = executor.run(cmd)
        return jsonify(result)

    @app.route("/api/tools/<tool>", methods=["POST"])
    def api_tool(tool: str):
        data = request.get_json(force=True) or {}
        err = validate_tool_params(tool, data)
        if err:
            return jsonify({"ok": False, "error": err}), 400
        try:
            cmd = build_command(tool, data)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        result = executor.run(cmd)
        parsed = parse_tool_output(tool, result.get("stdout", ""), result.get("stderr", ""))
        result.update({"parsed": parsed, "lines": parsed.get("lines")})
        
        # Clean up temporary resource file if it was created
        if "_temp_rc_file" in data:
            try:
                os.remove(data["_temp_rc_file"])
                logging.info(f"Cleaned up temporary Metasploit resource file: {data['_temp_rc_file']}")
            except OSError as e:
                logging.error(f"Error cleaning up temporary file {data['_temp_rc_file']}: {e}")

        return jsonify(result)

    @app.route("/api/catalog/installed", methods=["GET"])
    def catalog_installed():
        names = supported_tools()
        status = tools_status_map(names)
        installed = [n for n, ok in status.items() if ok]
        return jsonify({"ok": True, "supported": names, "installed": installed, "status": status})

    @app.route("/api/catalog/pentest_windows", methods=["GET"])
    def catalog_pentest_windows():
        branch = request.args.get("branch", "main")
        md = fetch_pentest_windows_readme(branch)
        if not md:
            return jsonify({"ok": False, "error": "Failed to fetch README from GitHub"}), 502
        tools = parse_tools_from_readme(md)
        return jsonify({"ok": True, "source": f"arch3rPro/Pentest-Windows@{branch}", "tools": tools})

    @app.route("/health", methods=["GET"])
    def health():
        names = supported_tools()
        status = tools_status_map(names)
        essential_ok = all(status.get(t, False) for t in ESSENTIAL_TOOLS)
        return jsonify({"status": "ok", "ok": True, "tools_status": status, "all_essential_tools_available": essential_ok})

    @app.route("/mcp/capabilities", methods=["GET"])
    def mcp_caps():
        return jsonify({"ok": True, "tools": supported_tools(), "endpoints": ["/api/tools/<tool>", "/api/command", "/health", "/api/catalog/*"]})

    @app.route("/mcp/tools/pst_tools/<tool>", methods=["POST"])
    def mcp_pst_tool(tool: str):
        data = request.get_json(force=True) or {}
        err = validate_tool_params(tool, data)
        if err:
            return jsonify({"ok": False, "error": err}), 400
        try:
            cmd = build_command(tool, data)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        result = executor.run(cmd)
        parsed = parse_tool_output(tool, result.get("stdout", ""), result.get("stderr", ""))
        result.update({"parsed": parsed, "lines": parsed.get("lines")})

        # Clean up temporary resource file if it was created
        if "_temp_rc_file" in data:
            try:
                os.remove(data["_temp_rc_file"])
                logging.info(f"Cleaned up temporary Metasploit resource file: {data['_temp_rc_file']}")
            except OSError as e:
                logging.error(f"Error cleaning up temporary file {data['_temp_rc_file']}: {e}")

        return jsonify(result)

    return app

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser("PST Windows API Server")
    parser.add_argument("--port", type=int, default=5100)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()

def main():
    args = parse_args()
    executor = CommandExecutor(timeout=args.timeout)
    app = create_app(executor)
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()