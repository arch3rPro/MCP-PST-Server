import argparse
import json
import os
import platform
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
        "metasploit", "john", "nikto", "gobuster", "masscan", "netcat", "ehole", "bbot", "amass", "enscan", "searchsploit", "githacker", "gowitness", "seclists",
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
            # 处理常见的NSE脚本问题
            # 如果是"default"，替换为更具体的脚本类别，避免NSE引擎初始化失败
            if script_scan == "default":
                script_scan = "auth,banner,brute,default,discovery,external,intrusive,malware,safe,vuln"
            
            # 验证脚本名称格式，处理逗号分隔的多个脚本
            scripts = [s.strip() for s in script_scan.split(',')]
            valid_scripts = []
            
            for script in scripts:
                # 跳过空脚本名
                if not script:
                    continue
                
                # 移除.nse扩展名（如果存在）
                if script.endswith('.nse'):
                    script = script[:-4]
                
                # 如果脚本包含路径分隔符，可能是完整路径，直接使用
                if '/' in script or '\\' in script:
                    if os.path.exists(script):
                        valid_scripts.append(script)
                    continue
                
                # 检查常见脚本名称
                common_scripts = [
                    "ssh2-enum-algos", "ssh-hostkey", "ssh-auth-methods", "ssh-run",
                    "http-enum", "http-title", "http-headers", "http-methods", "http-ntlm-info",
                    "smb-enum-shares", "smb-enum-users", "smb-os-discovery",
                    "ftp-anon", "ftp-bounce", "ftp-libopie", "ftp-proftpd-backdoor",
                    "mysql-info", "mysql-enum", "mysql-vulns",
                    "postgresql-brute", "postgresql-info",
                    "redis-info", "mongodb-info", "elasticsearch-info",
                    "ssl-enum-ciphers", "ssl-cert", "ssl-heartbleed",
                    "dns-brute", "dns-zone-transfer", "dns-nsec-enum",
                    "snmp-brute", "snmp-info", "snmp-interfaces"
                ]
                
                # 如果是常见脚本，直接添加
                if script in common_scripts:
                    valid_scripts.append(script)
                # 如果是脚本类别，直接添加
                elif script in ["auth", "banner", "brute", "default", "discovery", "external", "intrusive", "malware", "safe", "vuln"]:
                    valid_scripts.append(script)
                # 否则，尝试检查脚本文件是否存在
                else:
                    # 尝试常见路径
                    script_paths = [
                        f"/usr/share/nmap/scripts/{script}.nse",
                        f"/usr/local/share/nmap/scripts/{script}.nse",
                        f"C:\\Program Files\\Nmap\\scripts\\{script}.nse",
                        f"{script}.nse"  # 相对路径
                    ]
                    
                    script_found = False
                    for path in script_paths:
                        if os.path.exists(path):
                            valid_scripts.append(script)
                            script_found = True
                            break
                    
                    # 如果脚本未找到，仍然添加到列表中，让nmap自己处理错误
                    if not script_found:
                        valid_scripts.append(script)
            
            # 只有在有有效脚本时才添加--script参数
            if valid_scripts:
                cmd += ["--script", ",".join(valid_scripts)]
            
        # 添加脚本参数
        if script_args:
            # 处理常见的NSE脚本参数问题
            # 确保参数格式正确，避免解析失败
            # 脚本参数应该是 key=value;key2=value2 的格式
            
            # 移除可能存在的前缀 --script-args=
            if script_args.startswith("--script-args="):
                script_args = script_args[len("--script-args="):]
            elif script_args.startswith("--script-args "):
                script_args = script_args[len("--script-args "):]
            
            # 检查参数格式，如果没有等号，可能是格式错误
            if '=' not in script_args and ';' not in script_args:
                # 尝试修复常见格式问题
                # 如果只是一个值，可能需要添加键名
                if script_args and not any(c in script_args for c in ['=', ';', ',']):
                    # 对于简单值，添加默认键名
                    script_args = f"args={script_args}"
            
            # 进一步验证和清理参数
            args_list = []
            for arg in script_args.split(';'):
                arg = arg.strip()
                if not arg:
                    continue
                
                # 确保每个参数都有键值对
                if '=' in arg:
                    key, value = arg.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # 清理键名中的特殊字符
                    key = ''.join(c for c in key if c.isalnum() or c in ['_', '-'])
                    
                    # 清理值中的特殊字符
                    if value:
                        # 如果值包含空格，添加引号
                        if ' ' in value and not (value.startswith('"') and value.endswith('"')):
                            value = f'"{value}"'
                        
                        args_list.append(f"{key}={value}")
                else:
                    # 对于没有等号的参数，尝试添加默认键名
                    args_list.append(f"arg={arg}")
            
            # 只有在有有效参数时才添加--script-args参数
            if args_list:
                cmd += ["--script-args", ";".join(args_list)]
            
        # 添加端口范围
        if ports:
            cmd += ["-p", ports]
            
        # 添加输出格式和文件
        if output_format and output_file:
            # 直接使用用户指定的输出格式
            if output_format.startswith("-o"):
                cmd += [output_format, output_file]
            else:
                # 如果不是标准的输出格式选项，假设是格式类型
                # 使用XML作为默认格式
                cmd += ["-oX", output_file]
        elif output_format:
            # 处理只有输出格式没有文件的情况
            if output_format.startswith("-o"):
                cmd += [output_format]
            else:
                # 对于非标准格式，使用XML
                import tempfile
                temp_file = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
                output_file = temp_file.name
                temp_file.close()
                cmd += ["-oX", output_file]
            
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
        status_code = data.get("status_code", True)
        title = data.get("title", True)
        tech_detect = data.get("tech_detect", True)
        content_length = data.get("content_length", False)
        jarm = data.get("jarm", False)
        follow_redirects = data.get("follow_redirects", False)
        
        cmd = ["httpx", "-silent", "-no-color"]
        
        # Add status code flag
        if status_code:
            cmd += ["-status-code"]
        
        # Add title flag
        if title:
            cmd += ["-title"]
        
        # Add technology detection flag
        if tech_detect:
            cmd += ["-tech-detect"]
        
        # Add content length flag
        if content_length:
            cmd += ["-content-length"]
        
        # Add JARM flag
        if jarm:
            cmd += ["-jarm"]
        
        # Add follow redirects flag
        if follow_redirects:
            cmd += ["-follow-redirects"]
        
        # Add target or list file
        if list_file:
            # 确保文件路径存在且可读
            import os
            if not os.path.exists(list_file):
                raise ValueError(f"List file not found: {list_file}")
            if not os.path.isfile(list_file):
                raise ValueError(f"Path is not a file: {list_file}")
            if not os.access(list_file, os.R_OK):
                raise ValueError(f"File is not readable: {list_file}")
            cmd += ["-l", list_file]
        elif target:
            cmd += ["-u", target]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "ffuf":
        url = data.get("url", "")
        wordlist = data.get("wordlist", "")
        method = data.get("method", "GET")
        headers = data.get("headers", "")
        post_data = data.get("data", "")
        cookies = data.get("cookies", "")
        match_status = data.get("match_status", "")
        filter_status = data.get("filter_status", "")
        match_size = data.get("match_size", "")
        filter_size = data.get("filter_size", "")
        match_words = data.get("match_words", "")
        filter_words = data.get("filter_words", "")
        
        cmd = ["ffuf"]
        
        # Add URL with FUZZ keyword
        if url:
            cmd += ["-u", url]
        
        # Add wordlist
        if wordlist:
            cmd += ["-w", wordlist]
        else:
            # 如果没有指定wordlist，尝试使用SecLists中的默认web目录字典
            seclists_path = data.get("seclists_path", "D:\\Global\\apps\\SecLists\\current")
            # 常用的web目录扫描字典路径
            default_wordlists = [
                os.path.join(seclists_path, "Discovery", "Web-Content", "common.txt"),
                os.path.join(seclists_path, "Discovery", "Web-Content", "directory-list-lowercase-2.3-small.txt")
            ]
            
            # 检查默认字典文件是否存在
            for wl_path in default_wordlists:
                if os.path.exists(wl_path):
                    cmd += ["-w", wl_path]
                    break
        
        # Add HTTP method
        if method:
            cmd += ["-X", method]
        
        # Add headers
        if headers:
            for header in headers.split(","):
                header = header.strip()
                if header:
                    cmd += ["-H", header]
        
        # Add POST data
        if post_data:
            cmd += ["-d", post_data]
        
        # Add cookies
        if cookies:
            cmd += ["-b", cookies]
        
        # Add match status codes
        if match_status:
            cmd += ["-mc", match_status]
        
        # Add filter status codes
        if filter_status:
            cmd += ["-fc", filter_status]
        
        # Add match response size
        if match_size:
            cmd += ["-ms", match_size]
        
        # Add filter response size
        if filter_size:
            cmd += ["-fs", filter_size]
        
        # Add match response words
        if match_words:
            cmd += ["-mw", match_words]
        
        # Add filter response words
        if filter_words:
            cmd += ["-fw", filter_words]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "feroxbuster":
        url = data.get("url", "")
        extensions = data.get("extensions", "")
        methods = data.get("methods", "")
        headers = data.get("headers", "")
        cookies = data.get("cookies", "")
        status_codes = data.get("status_codes", "")
        threads = data.get("threads", "")
        no_recursion = data.get("no_recursion", False)
        depth = data.get("depth", "")
        wordlist = data.get("wordlist", "")
        rate_limit = data.get("rate_limit", "")
        time_limit = data.get("time_limit", "")
        silent = data.get("silent", False)
        json = data.get("json", False)
        output = data.get("output", "")
        burp = data.get("burp", False)
        
        cmd = ["feroxbuster"]
        
        # Add URL
        if url:
            cmd += ["-u", url]
        
        # Add extensions
        if extensions:
            cmd += ["-x", extensions]
        
        # Add HTTP methods
        if methods:
            for method in methods.split(","):
                method = method.strip()
                if method:
                    cmd += ["-m", method]
        
        # Add headers
        if headers:
            for header in headers.split(","):
                header = header.strip()
                if header:
                    cmd += ["-H", header]
        
        # Add cookies
        if cookies:
            for cookie in cookies.split(","):
                cookie = cookie.strip()
                if cookie:
                    cmd += ["-b", cookie]
        
        # Add status codes
        if status_codes:
            cmd.append("-s")
            for code in status_codes.split(","):
                code = code.strip()
                if code:
                    cmd.append(code)
        
        # Add threads
        if threads:
            cmd += ["-t", threads]
        
        # Add no recursion flag
        if no_recursion:
            cmd += ["-n"]
        
        # Add recursion depth
        if depth:
            cmd += ["--depth", depth]
        
        # Add wordlist
        if wordlist:
            cmd += ["-w", wordlist]
        
        # Add rate limit
        if rate_limit:
            cmd += ["--rate-limit", rate_limit]
        
        # Add time limit
        if time_limit:
            cmd += ["--time-limit", time_limit]
        
        # Add silent flag
        if silent:
            cmd += ["-q"]
        
        # Add JSON output flag
        if json:
            cmd += ["--json"]
        
        # Add output file
        if output:
            cmd += ["-o", output]
        
        # Add Burp flag
        if burp:
            cmd += ["--burp"]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "fscan":
        target = data.get("target", "")
        ports = data.get("ports", "")
        username = data.get("username", "")
        password = data.get("password", "")
        scan_mode = data.get("scan_mode", "All")
        threads = data.get("threads", "60")
        timeout = data.get("timeout", "3")
        url = data.get("url", "")
        proxy = data.get("proxy", "")
        output_file = data.get("output_file", "result.txt")
        
        cmd = ["fscan", "-h", target]
        
        # Add ports
        if ports:
            cmd += ["-p", ports]
        
        # Add username
        if username:
            cmd += ["-user", username]
        
        # Add password
        if password:
            cmd += ["-pwd", password]
        
        # Add scan mode
        if scan_mode:
            cmd += ["-m", scan_mode]
        
        # Add threads
        if threads:
            cmd += ["-t", threads]
        
        # Add timeout
        if timeout:
            cmd += ["-time", timeout]
        
        # Add URL
        if url:
            cmd += ["-url", url]
        
        # Add proxy
        if proxy:
            cmd += ["-proxy", proxy]
        
        # Add output file
        if output_file:
            cmd += ["-o", output_file]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "hydra":
        target = data.get("target", "")
        service = data.get("service", "ssh")
        username = data.get("username", "")
        username_file = data.get("username_file", "")
        password = data.get("password", "")
        password_file = data.get("password_file", "")
        port = data.get("port", "")
        tasks = data.get("tasks", "")
        wait_time = data.get("wait_time", "")
        timeout = data.get("timeout", "")
        login_attempts = data.get("login_attempts", "")
        retry_time = data.get("retry_time", "")
        exit_on_success = data.get("exit_on_success", "")
        skip_default_passwords = data.get("skip_default_passwords", "")
        skip_empty_passwords = data.get("skip_empty_passwords", "")
        skip_login = data.get("skip_login", "")
        use_ssl = data.get("use_ssl", "")
        
        cmd = ["hydra"]
        
        # Add username or username file
        if username_file:
            cmd += ["-L", username_file]
        elif username:
            cmd += ["-l", username]
        
        # Add password or password file
        if password_file:
            cmd += ["-P", password_file]
        elif password:
            cmd += ["-p", password]
        
        # Add port if specified
        if port:
            cmd += ["-s", port]
        
        # Add tasks/threads if specified
        if tasks:
            cmd += ["-t", tasks]
        
        # Add wait time if specified
        if wait_time:
            cmd += ["-w", wait_time]
        
        # Add timeout if specified
        if timeout:
            cmd += ["-w", timeout]
        
        # Add login attempts if specified
        if login_attempts:
            cmd += ["-m", login_attempts]
        
        # Add retry time if specified
        if retry_time:
            cmd += ["-w", retry_time]
        
        # Add exit on success flag
        if exit_on_success:
            cmd += ["-f"]
        
        # Add skip default passwords flag
        if skip_default_passwords:
            cmd += ["-e", "nsr"]
        
        # Add skip empty passwords flag
        if skip_empty_passwords:
            cmd += ["-e", "n"]
        
        # Add skip login flag
        if skip_login:
            cmd += ["-e", "s"]
        
        # Add SSL flag
        if use_ssl:
            cmd += ["-S"]
        
        # Add target and service
        if target and service:
            cmd += [f"{service}://{target}"]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "hackbrowserdata":
        browser = data.get("browser", "")
        output_dir = data.get("output_dir", "./hbdata_output")
        
        cmd = ["hackbrowserdata"]
        
        # Add output directory
        if output_dir:
            cmd += ["-o", output_dir]
        
        # Add browser
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
        cookie = data.get("cookie", "")
        headers = data.get("headers", "")
        proxy = data.get("proxy", "")
        level = data.get("level", "1")
        risk = data.get("risk", "1")
        dbms = data.get("dbms", "")
        technique = data.get("technique", "BEUST")
        batch = data.get("batch", True)
        threads = data.get("threads", "1")
        dbs = data.get("dbs", False)
        tables = data.get("tables", False)
        columns = data.get("columns", False)
        dump = data.get("dump", False)
        
        cmd = [sys.executable, "-m", "sqlmap", "-u", url]
        
        # Add POST data
        if post_data:
            cmd += ["--data", post_data]
        
        # Add cookie
        if cookie:
            cmd += ["--cookie", cookie]
        
        # Add headers
        if headers:
            cmd += ["--headers", headers]
        
        # Add proxy
        if proxy:
            cmd += ["--proxy", proxy]
        
        # Add level
        if level:
            cmd += ["--level", str(level)]
        
        # Add risk
        if risk:
            cmd += ["--risk", str(risk)]
        
        # Add DBMS
        if dbms:
            cmd += ["--dbms", dbms]
        
        # Add technique
        if technique:
            cmd += ["--technique", technique]
        
        # Add batch mode
        if batch:
            cmd += ["--batch"]
        
        # Add threads
        if threads:
            cmd += ["--threads", str(threads)]
        
        # Add dbs flag
        if dbs:
            cmd += ["--dbs"]
        
        # Add tables flag
        if tables:
            cmd += ["--tables"]
        
        # Add columns flag
        if columns:
            cmd += ["--columns"]
        
        # Add dump flag
        if dump:
            cmd += ["--dump"]
        
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

    if tool == "amass":
        target = data.get("target", "")
        mode = data.get("mode", "enum")
        passive = data.get("passive", False)
        active = data.get("active", True)
        brute = data.get("brute", False)
        min_for_recursive = data.get("min_for_recursive", 1)
        max_dns_queries = data.get("max_dns_queries", 10000)
        timeout = data.get("timeout", 30)
        include_unresolvable = data.get("include_unresolvable", False)
        output_file = data.get("output_file", "")
        
        cmd = ["amass", mode]
        
        # Add target
        if target:
            cmd += ["-d", target]
        
        # Add passive mode
        if passive:
            cmd += ["-passive"]
        
        # Add active mode
        if active:
            cmd += ["-active"]
        
        # Add brute force
        if brute:
            cmd += ["-brute"]
        
        # Add minimum for recursive
        if min_for_recursive:
            cmd += ["-min-for-recursive", str(min_for_recursive)]
        
        # Add max DNS queries
        if max_dns_queries:
            cmd += ["-max-dns-queries", str(max_dns_queries)]
        
        # Add timeout
        if timeout:
            cmd += ["-timeout", str(timeout)]
        
        # Add include unresolvable
        if include_unresolvable:
            cmd += ["-include-unresolvable"]
        
        # Add output file
        if output_file:
            cmd += ["-o", output_file]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "enscan":
        keyword = data.get("keyword", "")
        company_id = data.get("company_id", "")
        input_file = data.get("input_file", "")
        is_pid = data.get("is_pid", "")
        scan_type = data.get("scan_type", "aqc")
        field = data.get("field", "")
        invest = data.get("invest", "")
        deep = data.get("deep", "0")
        hold = data.get("hold", "")
        supplier = data.get("supplier", "")
        branch = data.get("branch", "")
        is_branch = data.get("is_branch", "")
        branch_filter = data.get("branch_filter", "")
        out_dir = data.get("out_dir", "outs")
        out_type = data.get("out_type", "xlsx")
        json = data.get("json", "")
        no_merge = data.get("no_merge", "")
        is_show = data.get("is_show", "")
        delay = data.get("delay", "0")
        proxy = data.get("proxy", "")
        timeout = data.get("timeout", "1")
        debug = data.get("debug", "")
        
        cmd = ["ENScan_GO"]
        
        # Add keyword
        if keyword:
            cmd += ["-n", keyword]
        
        # Add company ID
        if company_id:
            cmd += ["-i", company_id]
        
        # Add input file
        if input_file:
            cmd += ["-f", input_file]
        
        # Add is_pid flag
        if is_pid:
            cmd += ["-is-pid"]
        
        # Add scan type
        if scan_type:
            cmd += ["-type", scan_type]
        
        # Add field
        if field:
            cmd += ["-field", field]
        
        # Add invest
        if invest:
            cmd += ["-invest", invest]
        
        # Add deep
        if deep and deep != "0":
            cmd += ["-deep", deep]
        
        # Add hold flag
        if hold:
            cmd += ["-hold"]
        
        # Add supplier flag
        if supplier:
            cmd += ["-supplier"]
        
        # Add branch flag
        if branch:
            cmd += ["-branch"]
        
        # Add is_branch flag
        if is_branch:
            cmd += ["-is-branch"]
        
        # Add branch filter
        if branch_filter:
            cmd += ["-branch-filter", branch_filter]
        
        # Add output directory
        if out_dir:
            cmd += ["-out-dir", out_dir]
        
        # Add output type
        if out_type:
            cmd += ["-out-type", out_type]
        
        # Add JSON format
        if json:
            cmd += ["-json"]
        
        # Add no_merge flag
        if no_merge:
            cmd += ["-no-merge"]
        
        # Add is_show flag
        if is_show:
            cmd += ["-is-show"]
        
        # Add delay
        if delay and delay != "0":
            cmd += ["-delay", delay]
        
        # Add proxy
        if proxy:
            cmd += ["-proxy", proxy]
        
        # Add timeout
        if timeout and timeout != "1":
            cmd += ["-timeout", timeout]
        
        # Add debug flag
        if debug:
            cmd += ["-debug"]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "searchsploit":
        term = data.get("term", "")
        title = data.get("title", "")
        path = data.get("path", "")
        platform_param = data.get("platform", "")
        type = data.get("type", "")
        author = data.get("author", "")
        cve = data.get("cve", "")
        date = data.get("date", "")
        description = data.get("description", "")
        nmap = data.get("nmap", "")
        vulns = data.get("vulns", "")
        cbb = data.get("cbb", "")
        osh = data.get("osh", "")
        st = data.get("st", "")
        www = data.get("www", "")
        pb = data.get("pb", "")
        pi = data.get("pi", "")
        rfi = data.get("rfi", "")
        lfi = data.get("lfi", "")
        sqli = data.get("sqli", "")
        xss = data.get("xss", "")
        shell = data.get("shell", "")
        android = data.get("android", "")
        dos = data.get("dos", "")
        local = data.get("local", "")
        remote = data.get("remote", "")
        web = data.get("web", "")
        wifi = data.get("wifi", "")
        windows = data.get("windows", "")
        exclude = data.get("exclude", "")
        case_sensitive = data.get("case_sensitive", "")
        count = data.get("count", "")
        id = data.get("id", "")
        mirror = data.get("mirror", "")
        nmap_file = data.get("nmap_file", "")
        searchsploit_path = data.get("searchsploit_path", "")
        update = data.get("update", "")
        colour = data.get("colour", "")
        disable_color = data.get("disable_color", "")
        json_output = data.get("json_output", "")
        edb_id = data.get("edb_id", "")
        github = data.get("github", "")
        exploitdb_path = data.get("exploitdb_path", "")
        
        # 根据平台选择正确的命令
        if platform.system() == "Windows":
            cmd = ["searchsploit.cmd"]
        else:
            cmd = ["searchsploit"]
        
        # Add term
        if term:
            cmd.append(term)
        
        # Add title
        if title:
            cmd.extend(["-t", title])
        
        # Add path
        if path:
            cmd.extend(["-p", path])
        
        # Add platform
        if platform_param:
            cmd.extend(["--platform", platform_param])
        
        # Add type
        if type:
            cmd.extend(["--type", type])
        
        # Add author
        if author:
            cmd.extend(["--author", author])
        
        # Add CVE
        if cve:
            cmd.extend(["--cve", cve])
        
        # Add date
        if date:
            cmd.extend(["--date", date])
        
        # Add description
        if description:
            cmd.extend(["--description", description])
        
        # Add nmap
        if nmap:
            cmd.append("--nmap")
        
        # Add vulns
        if vulns:
            cmd.append("--vulns")
        
        # Add cbb
        if cbb:
            cmd.append("--cbb")
        
        # Add osh
        if osh:
            cmd.append("--osh")
        
        # Add st
        if st:
            cmd.append("--st")
        
        # Add www
        if www:
            cmd.append("--www")
        
        # Add pb
        if pb:
            cmd.append("--pb")
        
        # Add pi
        if pi:
            cmd.append("--pi")
        
        # Add rfi
        if rfi:
            cmd.append("--rfi")
        
        # Add lfi
        if lfi:
            cmd.append("--lfi")
        
        # Add sqli
        if sqli:
            cmd.append("--sqli")
        
        # Add xss
        if xss:
            cmd.append("--xss")
        
        # Add shell
        if shell:
            cmd.append("--shell")
        
        # Add android
        if android:
            cmd.append("--android")
        
        # Add dos
        if dos:
            cmd.append("--dos")
        
        # Add local
        if local:
            cmd.append("--local")
        
        # Add remote
        if remote:
            cmd.append("--remote")
        
        # Add web
        if web:
            cmd.append("--web")
        
        # Add wifi
        if wifi:
            cmd.append("--wifi")
        
        # Add windows
        if windows:
            cmd.append("--windows")
        
        # Add exclude
        if exclude:
            cmd.extend(["--exclude", exclude])
        
        # Add case_sensitive
        if case_sensitive:
            cmd.append("--case-sensitive")
        
        # Add count
        if count:
            cmd.append("--count")
        
        # Add id
        if id:
            cmd.extend(["-id", id])
        
        # Add mirror
        if mirror:
            cmd.append("--mirror")
        
        # Add nmap_file
        if nmap_file:
            cmd.extend(["-nmap", nmap_file])
        
        # Add searchsploit_path
        if searchsploit_path:
            cmd.extend(["--searchsploit-path", searchsploit_path])
        
        # Add update
        if update:
            cmd.append("--update")
        
        # Add colour
        if colour:
            cmd.extend(["--colour", colour])
        
        # Add disable_color
        if disable_color:
            cmd.append("--disable-colour")
        
        # Add json_output
        if json_output:
            cmd.append("--json")
        
        # Add edb_id
        if edb_id:
            cmd.extend(["--edb-id", edb_id])
        
        # Add github
        if github:
            cmd.extend(["--github", github])
        
        # Add exploitdb_path
        if exploitdb_path:
            cmd.extend(["--exploitdb-path", exploitdb_path])
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "githacker":
        url = data.get("url", "")
        output = data.get("output", "")
        threads = data.get("threads", "")
        brute = data.get("brute", False)
        url_file = data.get("url_file", "")
        
        cmd = ["githacker"]
        
        # 添加URL
        if url:
            cmd += ["--url", url]
        
        # 添加输出目录
        if output:
            cmd += ["--output-folder", output]
        
        # 添加线程数
        if threads:
            cmd += ["--threads", str(threads)]
        
        # 添加暴力破解标志
        if brute:
            cmd += ["--brute"]
        
        # 添加URL文件
        if url_file:
            cmd += ["--url-file", url_file]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "gowitness":
        scan_type = data.get("scan_type", "single")
        url = data.get("url", "")
        file = data.get("file", "")
        cidr = data.get("cidr", "")
        nmap_file = data.get("nmap_file", "")
        nessus_file = data.get("nessus_file", "")
        threads = data.get("threads", "")
        timeout = data.get("timeout", "")
        delay = data.get("delay", "")
        screenshot_path = data.get("screenshot_path", "")
        screenshot_format = data.get("screenshot_format", "")
        chrome_path = data.get("chrome_path", "")
        chrome_proxy = data.get("chrome_proxy", "")
        chrome_user_agent = data.get("chrome_user_agent", "")
        write_db = data.get("write_db", False)
        write_csv = data.get("write_csv", False)
        write_jsonl = data.get("write_jsonl", False)
        screenshot_fullpage = data.get("screenshot_fullpage", False)
        save_content = data.get("save_content", False)
        
        # 基础命令
        cmd = ["gowitness", "scan", scan_type]
        
        # 根据扫描类型添加参数
        if scan_type == "single" and url:
            cmd += ["-u", url]
        elif scan_type == "file" and file:
            cmd += ["-f", file]
        elif scan_type == "cidr" and cidr:
            cmd += ["-c", cidr]
        elif scan_type == "nmap" and nmap_file:
            cmd += ["-f", nmap_file]
        elif scan_type == "nessus" and nessus_file:
            cmd += ["-f", nessus_file]
        
        # 添加线程数
        if threads:
            cmd += ["-t", str(threads)]
        
        # 添加超时时间
        if timeout:
            cmd += ["-T", str(timeout)]
        
        # 添加延迟
        if delay:
            cmd += ["--delay", str(delay)]
        
        # 添加截图保存路径
        if screenshot_path:
            cmd += ["-s", screenshot_path]
        
        # 添加截图格式
        if screenshot_format:
            cmd += ["--screenshot-format", screenshot_format]
        
        # 添加Chrome路径
        if chrome_path:
            cmd += ["--chrome-path", chrome_path]
        
        # 添加Chrome代理
        if chrome_proxy:
            cmd += ["--chrome-proxy", chrome_proxy]
        
        # 添加Chrome用户代理
        if chrome_user_agent:
            cmd += ["--chrome-user-agent", chrome_user_agent]
        
        # 添加写入数据库标志
        if write_db:
            cmd += ["--write-db"]
        
        # 添加写入CSV标志
        if write_csv:
            cmd += ["--write-csv"]
        
        # 添加写入JSONL标志
        if write_jsonl:
            cmd += ["--write-jsonl"]
        
        # 添加全页截图标志
        if screenshot_fullpage:
            cmd += ["--screenshot-fullpage"]
        
        # 添加保存内容标志
        if save_content:
            cmd += ["--save-content"]
        
        return add_args(cmd, data.get("additional_args", ""))

    if tool == "seclists":
        action = data.get("action", "list")
        category = data.get("category", "")
        list_type = data.get("list_type", "")
        output_file = data.get("output_file", "")
        seclists_path = data.get("seclists_path", "D:\\Global\\apps\\SecLists\\current")
        copy_to_workdir = data.get("copy_to_workdir", False)
        workdir_path = data.get("workdir_path", "")
        return_content = data.get("return_content", False)
        max_lines = data.get("max_lines", 1000)
        
        # SecLists是一个字典文件集合，不需要执行外部命令
        # 使用Python直接处理文件系统操作
        cmd = [sys.executable, "-c", f"""
import os
import sys
import json
seclists_path = r"{seclists_path}"
action = "{action}"
category = "{category}"
list_type = "{list_type}"
output_file = "{output_file}"
copy_to_workdir = {copy_to_workdir}
workdir_path = r"{workdir_path}"
return_content = {return_content}
max_lines = {max_lines}

# 模拟seclists工具的输出
print(f"SecLists Path: {{seclists_path}}")
print(f"Action: {{action}}")
print(f"Category: {{category}}")
print(f"List Type: {{list_type}}")

if os.path.exists(seclists_path) and os.path.isdir(seclists_path):
    print("SecLists directory found")
    if action == "list":
        # 列出可用的分类和文件
        categories = []
        for item in os.listdir(seclists_path):
            item_path = os.path.join(seclists_path, item)
            if os.path.isdir(item_path):
                categories.append(item)
        print(f"Available categories: {{', '.join(categories)}}")
    
    if category and list_type:
        # 模拟获取特定字典文件
        target_file = os.path.join(seclists_path, category, f"{{list_type}}.txt")
        if os.path.exists(target_file):
            print(f"Dictionary file found: {{target_file}}")
            if return_content:
                try:
                    with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[:max_lines]
                        content = ''.join(lines)
                        print(f"Content preview (first {{len(lines)}} lines):")
                        print(content)
                except Exception as e:
                    print(f"Error reading file: {{e}}")
            if output_file:
                print(f"Output would be saved to: {{output_file}}")
            if copy_to_workdir and workdir_path:
                print(f"File would be copied to: {{workdir_path}}")
        else:
            print(f"Dictionary file not found: {{target_file}}")
            print("Available files in category:")
            category_path = os.path.join(seclists_path, category)
            if os.path.exists(category_path):
                for file in os.listdir(category_path):
                    if file.endswith('.txt'):
                        print(f"  {{file}}")
else:
    print(f"SecLists directory not found: {{seclists_path}}")
    print("Please ensure SecLists is installed at the specified path")
"""]
        
        return cmd

    raise ValueError(f"Unsupported tool: {tool}")

def shutil_which(name: str) -> Optional[str]:
    from shutil import which
    return which(name)

ALIAS_BINARIES = {
    "metasploit": ["msfconsole"],
    "netcat": ["ncat", "nc"],
    "ehole": ["EHole", "ehole"],
    "searchsploit": ["searchsploit.cmd", "searchsploit"],
    "githacker": ["githacker"],
    "gowitness": ["gowitness"],
    "seclists": ["seclists"],
}

def tools_status_map(names: List[str]) -> Dict[str, bool]:
    status: Dict[str, bool] = {}
    for name in names:
        # Special handling for seclists - check if directory exists instead of executable
        if name == "seclists":
            seclists_path = "D:\\Global\\apps\\SecLists\\current"
            ok = os.path.exists(seclists_path) and os.path.isdir(seclists_path)
            status[name] = ok
        else:
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
    
    if tool == "amass":
        target = str(data.get("target", "")).strip()
        mode = str(data.get("mode", "enum")).strip()
        output_file = str(data.get("output_file", "")).strip()
        
        # Amass requires at least a target
        if not target:
            return "amass 需要提供 'target' 参数"
        
        # Validate mode
        valid_modes = ["enum", "track", "intel", "db"]
        if mode and mode not in valid_modes:
            return f"amass mode 必须是以下之一: {', '.join(valid_modes)}"
        
        # Check if output file directory exists if output_file is provided
        if output_file:
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                return f"输出目录不存在: {output_dir}"
    
    if tool == "enscan":
        keyword = str(data.get("keyword", "")).strip()
        company_id = str(data.get("company_id", "")).strip()
        input_file = str(data.get("input_file", "")).strip()
        out_dir = str(data.get("out_dir", "")).strip()
        scan_type = str(data.get("scan_type", "")).strip()
        invest = str(data.get("invest", "")).strip()
        deep = str(data.get("deep", "0")).strip()
        branch_filter = str(data.get("branch_filter", "")).strip()
        proxy = str(data.get("proxy", "")).strip()
        
        # ENScan requires at least one of keyword, company_id, or input_file
        if not any([keyword, company_id, input_file]):
            return "enscan 需要提供 'keyword', 'company_id', 或 'input_file' 之一"
        
        # Check if input file exists if provided
        if input_file and not os.path.exists(input_file):
            return f"输入文件不存在: {input_file}"
        
        # Check if output directory exists if provided
        if out_dir and not os.path.exists(out_dir):
            return f"输出目录不存在: {out_dir}"
        
        # Validate scan_type
        valid_scan_types = ["aqc", "tyc", "kc", "all"]
        if scan_type and scan_type not in valid_scan_types:
            return f"scan_type 必须是以下之一: {', '.join(valid_scan_types)}"
        
        # Validate deep
        if deep and not deep.isdigit():
            return "deep 必须是数字"
        
        # Validate invest if provided
        if invest:
            try:
                invest_value = float(invest)
                if invest_value < 0 or invest_value > 100:
                    return "invest 必须是0-100之间的数字"
            except ValueError:
                return "invest 必须是数字"
    
    if tool == "searchsploit":
        term = str(data.get("term", "")).strip()
        title = str(data.get("title", "")).strip()
        path = str(data.get("path", "")).strip()
        platform = str(data.get("platform", "")).strip()
        type = str(data.get("type", "")).strip()
        author = str(data.get("author", "")).strip()
        cve = str(data.get("cve", "")).strip()
        date = str(data.get("date", "")).strip()
        description = str(data.get("description", "")).strip()
        nmap_file = str(data.get("nmap_file", "")).strip()
        searchsploit_path = str(data.get("searchsploit_path", "")).strip()
        colour = str(data.get("colour", "")).strip()
        id = str(data.get("id", "")).strip()
        edb_id = str(data.get("edb_id", "")).strip()
        github = str(data.get("github", "")).strip()
        exploitdb_path = str(data.get("exploitdb_path", "")).strip()
        exclude = str(data.get("exclude", "")).strip()
        
        # SearchSploit requires at least one of term, title, cve, or id
        if not any([term, title, cve, id]):
            return "searchsploit 需要提供 'term', 'title', 'cve', 或 'id' 之一"
        
        # Check if path exists if provided
        if path and not os.path.exists(path):
            return f"路径不存在: {path}"
        
        # Check if nmap_file exists if provided
        if nmap_file and not os.path.exists(nmap_file):
            return f"Nmap文件不存在: {nmap_file}"
        
        # Check if searchsploit_path exists if provided
        if searchsploit_path and not os.path.exists(searchsploit_path):
            return f"SearchSploit路径不存在: {searchsploit_path}"
        
        # Check if exploitdb_path exists if provided
        if exploitdb_path and not os.path.exists(exploitdb_path):
            return f"ExploitDB路径不存在: {exploitdb_path}"
        
        # Validate platform
        valid_platforms = ["aix", "bsd", "bsd/x86", "bsd/x86-64", "cgi", "freebsd", "freebsd/x86", 
                           "freebsd/x86-64", "hardware", "hp-ux", "irix", "linux", "linux/x86", 
                           "linux/x86-64", "macos", "multiple", "netbsd", "netbsd/x86", 
                           "netbsd/x86-64", "novell", "openbsd", "openbsd/x86", "openbsd/x86-64", 
                           "osx", "sco", "solaris", "solaris/x86", "solaris/x86-64", "unix", 
                           "windows", "windows/x86", "windows/x86-64"]
        if platform and platform.lower() not in valid_platforms:
            return f"platform 必须是以下之一: {', '.join(valid_platforms)}"
        
        # Validate type
        valid_types = ["dos", "local", "remote", "shellcode", "webapps"]
        if type and type.lower() not in valid_types:
            return f"type 必须是以下之一: {', '.join(valid_types)}"
        
        # Validate colour
        valid_colours = ["0", "1", "2", "3", "4", "5", "6", "7", "always", "never", "auto"]
        if colour and colour.lower() not in valid_colours:
            return f"colour 必须是以下之一: {', '.join(valid_colours)}"
        
        # Validate date format (YYYY-MM-DD)
        if date:
            try:
                from datetime import datetime
                datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                return "date 必须是 YYYY-MM-DD 格式"
    
    if tool == "githacker":
        url = str(data.get("url", "")).strip()
        output = str(data.get("output", "")).strip()
        threads = str(data.get("threads", "")).strip()
        url_file = str(data.get("url_file", "")).strip()
        
        # GitHacker requires at least a URL or URL file
        if not url and not url_file:
            return "githacker 需要提供 'url' 或 'url_file' 之一"
        
        # Check if URL file exists if provided
        if url_file and not os.path.exists(url_file):
            return f"URL文件不存在: {url_file}"
        
        # Check if output directory exists if provided
        if output and not os.path.exists(output):
            return f"输出目录不存在: {output}"
        
        # Validate threads if provided
        if threads:
            try:
                threads_value = int(threads)
                if threads_value <= 0:
                    return "threads 必须是正整数"
            except ValueError:
                return "threads 必须是数字"
    
    if tool == "gowitness":
        scan_type = str(data.get("scan_type", "single")).strip()
        url = str(data.get("url", "")).strip()
        file = str(data.get("file", "")).strip()
        cidr = str(data.get("cidr", "")).strip()
        nmap_file = str(data.get("nmap_file", "")).strip()
        nessus_file = str(data.get("nessus_file", "")).strip()
        threads = str(data.get("threads", "")).strip()
        timeout = str(data.get("timeout", "")).strip()
        delay = str(data.get("delay", "")).strip()
        screenshot_path = str(data.get("screenshot_path", "")).strip()
        screenshot_format = str(data.get("screenshot_format", "")).strip()
        chrome_path = str(data.get("chrome_path", "")).strip()
        chrome_proxy = str(data.get("chrome_proxy", "")).strip()
        chrome_user_agent = str(data.get("chrome_user_agent", "")).strip()
        
        # Validate scan_type
        valid_scan_types = ["single", "file", "cidr", "nmap", "nessus"]
        if scan_type and scan_type not in valid_scan_types:
            return f"scan_type 必须是以下之一: {', '.join(valid_scan_types)}"
        
        # Validate required parameters based on scan_type
        if scan_type == "single" and not url:
            return "scan_type 为 'single' 时需要提供 'url' 参数"
        elif scan_type == "file" and not file:
            return "scan_type 为 'file' 时需要提供 'file' 参数"
        elif scan_type == "cidr" and not cidr:
            return "scan_type 为 'cidr' 时需要提供 'cidr' 参数"
        elif scan_type == "nmap" and not nmap_file:
            return "scan_type 为 'nmap' 时需要提供 'nmap_file' 参数"
        elif scan_type == "nessus" and not nessus_file:
            return "scan_type 为 'nessus' 时需要提供 'nessus_file' 参数"
        
        # Check if file exists if provided
        if file and not os.path.exists(file):
            return f"文件不存在: {file}"
        
        # Check if nmap_file exists if provided
        if nmap_file and not os.path.exists(nmap_file):
            return f"Nmap文件不存在: {nmap_file}"
        
        # Check if nessus_file exists if provided
        if nessus_file and not os.path.exists(nessus_file):
            return f"Nessus文件不存在: {nessus_file}"
        
        # Check if screenshot_path directory exists if provided
        if screenshot_path:
            screenshot_dir = os.path.dirname(screenshot_path)
            if screenshot_dir and not os.path.exists(screenshot_dir):
                return f"截图目录不存在: {screenshot_dir}"
        
        # Check if chrome_path exists if provided
        if chrome_path and not os.path.exists(chrome_path):
            return f"Chrome路径不存在: {chrome_path}"
        
        # Validate threads if provided
        if threads:
            try:
                threads_value = int(threads)
                if threads_value <= 0:
                    return "threads 必须是正整数"
            except ValueError:
                return "threads 必须是数字"
        
        # Validate timeout if provided
        if timeout:
            try:
                timeout_value = int(timeout)
                if timeout_value <= 0:
                    return "timeout 必须是正整数"
            except ValueError:
                return "timeout 必须是数字"
        
        # Validate delay if provided
        if delay:
            try:
                delay_value = float(delay)
                if delay_value < 0:
                    return "delay 必须是非负数"
            except ValueError:
                return "delay 必须是数字"
        
        # Validate screenshot_format if provided
        valid_formats = ["jpeg", "png"]
        if screenshot_format and screenshot_format.lower() not in valid_formats:
            return f"screenshot_format 必须是以下之一: {', '.join(valid_formats)}"
    
    if tool == "hydra":
        target = str(data.get("target", "")).strip()
        service = str(data.get("service", "")).strip()
        username = str(data.get("username", "")).strip()
        username_file = str(data.get("username_file", "")).strip()
        password = str(data.get("password", "")).strip()
        password_file = str(data.get("password_file", "")).strip()
        port = str(data.get("port", "")).strip()
        tasks = str(data.get("tasks", "")).strip()
        wait_time = str(data.get("wait_time", "")).strip()
        timeout = str(data.get("timeout", "")).strip()
        login_attempts = str(data.get("login_attempts", "")).strip()
        retry_time = str(data.get("retry_time", "")).strip()
        
        # Hydra requires at least target and service
        if not target:
            return "hydra 需要提供 'target' 参数"
        if not service:
            return "hydra 需要提供 'service' 参数"
        
        # Validate service
        valid_services = [
            "adam6500", "asterisk", "cisco", "cisco-enable", "cvs", "firebird", "ftp",
            "ftps", "http-head", "http-get", "http-post", "http-get-form", "http-post-form",
            "http-proxy", "http-proxy-urlenum", "icq", "imap", "imap3", "imaps", "irc",
            "ldap2", "ldap3", "ldap2-crammd5", "ldap3-crammd5", "ldap2-digestmd5",
            "ldap3-digestmd5", "mssql", "mysql", "nntp", "oracle-listener", "oracle-sid",
            "pcanywhere", "pcnfs", "pop3", "pop3s", "postgres", "radmin", "rdp", "redis",
            "rexec", "rlogin", "rpcap", "rsh", "rtsp", "s7-300", "s7-400", "s7-1200",
            "s7-1500", "sip", "smb", "smb2", "smtp", "smtps", "smtp-enum", "snmp",
            "socks5", "ssh", "sshkey", "svn", "teamspeak", "telnet", "tftp", "vmauthd",
            "vnc", "xmpp"
        ]
        if service.lower() not in valid_services:
            return f"service 必须是以下之一: {', '.join(valid_services[:10])}... (共{len(valid_services)}种服务)"
        
        # Check if username or username file is provided
        if not username and not username_file:
            return "hydra 需要提供 'username' 或 'username_file' 之一"
        
        # Check if password or password file is provided
        if not password and not password_file:
            return "hydra 需要提供 'password' 或 'password_file' 之一"
        
        # Check if username file exists if provided
        if username_file and not os.path.exists(username_file):
            return f"用户名文件不存在: {username_file}"
        
        # Check if password file exists if provided
        if password_file and not os.path.exists(password_file):
            return f"密码文件不存在: {password_file}"
        
        # Validate port if provided
        if port:
            try:
                port_value = int(port)
                if port_value < 1 or port_value > 65535:
                    return "port 必须是1-65535之间的整数"
            except ValueError:
                return "port 必须是数字"
        
        # Validate tasks if provided
        if tasks:
            try:
                tasks_value = int(tasks)
                if tasks_value < 1 or tasks_value > 256:
                    return "tasks 必须是1-256之间的整数"
            except ValueError:
                return "tasks 必须是数字"
        
        # Validate wait_time if provided
        if wait_time:
            try:
                wait_time_value = float(wait_time)
                if wait_time_value < 0:
                    return "wait_time 必须是非负数"
            except ValueError:
                return "wait_time 必须是数字"
        
        # Validate timeout if provided
        if timeout:
            try:
                timeout_value = int(timeout)
                if timeout_value < 1:
                    return "timeout 必须是正整数"
            except ValueError:
                return "timeout 必须是数字"
        
        # Validate login_attempts if provided
        if login_attempts:
            try:
                login_attempts_value = int(login_attempts)
                if login_attempts_value < 1:
                    return "login_attempts 必须是正整数"
            except ValueError:
                return "login_attempts 必须是数字"
        
        # Validate retry_time if provided
        if retry_time:
            try:
                retry_time_value = int(retry_time)
                if retry_time_value < 1:
                    return "retry_time 必须是正整数"
            except ValueError:
                return "retry_time 必须是数字"
    
    return None

def parse_tool_output(tool: str, stdout: str, stderr: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
    # Lightweight output parsing to aid readability; designed to be resilient
    lines = (stdout or "").splitlines()
    parsed: Dict[str, Any] = {"lines": lines}
    
    # 处理nmap工具的输出
    if tool == "nmap":
        # 从标准输出中提取基本信息
        # 提取主机信息
        hosts = []
        for m in re.finditer(r"Nmap scan report for ([^\s]+)", stdout or ""):
            hosts.append(m.group(1))
        
        # 提取端口信息
        ports = []
        for m in re.finditer(r"(\d+)/(\w+)\s+(\w+)\s+(\w+)", stdout or ""):
            port_info = {
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": m.group(3),
                "service": m.group(4)
            }
            ports.append(port_info)
        
        # 提取开放端口
        open_ports = [p["port"] for p in ports if p["state"] in ["open", "open|filtered"]]
        
        # 提取服务信息
        services = {}
        for port_info in ports:
            if port_info["state"] == "open":
                services[f"{port_info['port']}/{port_info['protocol']}"] = port_info["service"]
        
        # 提取操作系统信息
        os_info = []
        for m in re.finditer(r"OS details: (.+)", stdout or ""):
            os_info.append(m.group(1))
        
        # 提取脚本输出
        script_outputs = []
        script_pattern = r"\|_(.+)|\| (.+)"
        for m in re.finditer(script_pattern, stdout or ""):
            output = m.group(1) or m.group(2)
            if output and output.strip():
                script_outputs.append(output.strip())
        
        # 提取运行时间统计
        runtime_stats = []
        for m in re.finditer(r"(\w+) done in ([\d.]+) seconds", stdout or ""):
            runtime_stats.append({
                "task": m.group(1),
                "time": float(m.group(2))
            })
        
        # 更新解析结果
        parsed.update({
            "hosts": hosts,
            "ports": ports,
            "open_ports": sorted(open_ports),
            "services": services,
            "os_info": os_info,
            "script_outputs": script_outputs,
            "runtime_stats": runtime_stats,
            "format": "text",
            "source": "stdout_parsing"
        })
    
    elif tool == "ehole":
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
    elif tool == "amass":
        # Extract subdomains
        subdomains = []
        for m in re.finditer(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", stdout or "", re.MULTILINE):
            subdomains.append(m.group(0))
        
        # Extract IP addresses
        ips = []
        for m in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", stdout or ""):
            ips.append(m.group(0))
        
        # Extract URLs
        urls = []
        for m in re.finditer(r"https?://[^\s]+", stdout or ""):
            urls.append(m.group(0))
        
        # Extract email addresses
        emails = []
        for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", stdout or ""):
            emails.append(m.group(0))
        
        # Extract ASN information
        asns = []
        for m in re.finditer(r"ASN:\s*(\d+)", stdout or ""):
            asns.append(m.group(1))
        
        # Extract certificate information
        certificates = []
        for m in re.finditer(r"Certificate:\s*([^\n]+)", stdout or ""):
            certificates.append(m.group(1))
        
        parsed.update({
            "subdomains": subdomains,
            "ips": ips,
            "urls": urls,
            "emails": emails,
            "asns": asns,
            "certificates": certificates
        })
    elif tool == "enscan":
        # Extract company names
        companies = []
        for m in re.finditer(r"公司名称[：:]\s*([^\n]+)", stdout or ""):
            companies.append(m.group(1).strip())
        
        # Extract company IDs
        company_ids = []
        for m in re.finditer(r"公司ID[：:]\s*([^\n]+)", stdout or ""):
            company_ids.append(m.group(1).strip())
        
        # Extract legal representatives
        legal_reps = []
        for m in re.finditer(r"法定代表人[：:]\s*([^\n]+)", stdout or ""):
            legal_reps.append(m.group(1).strip())
        
        # Extract registration capital
        capital = []
        for m in re.finditer(r"注册资本[：:]\s*([^\n]+)", stdout or ""):
            capital.append(m.group(1).strip())
        
        # Extract establishment dates
        dates = []
        for m in re.finditer(r"成立日期[：:]\s*([^\n]+)", stdout or ""):
            dates.append(m.group(1).strip())
        
        # Extract business scopes
        scopes = []
        for m in re.finditer(r"经营范围[：:]\s*([^\n]+)", stdout or ""):
            scopes.append(m.group(1).strip())
        
        # Extract addresses
        addresses = []
        for m in re.finditer(r"地址[：:]\s*([^\n]+)", stdout or ""):
            addresses.append(m.group(1).strip())
        
        # Extract phone numbers
        phones = []
        for m in re.finditer(r"电话[：:]\s*([^\n]+)", stdout or ""):
            phones.append(m.group(1).strip())
        
        # Extract emails
        emails = []
        for m in re.finditer(r"邮箱[：:]\s*([^\n]+)", stdout or ""):
            emails.append(m.group(1).strip())
        
        # Extract websites
        websites = []
        for m in re.finditer(r"网站[：:]\s*([^\n]+)", stdout or ""):
            websites.append(m.group(1).strip())
        
        # Extract unified social credit codes
        credit_codes = []
        for m in re.finditer(r"统一社会信用代码[：:]\s*([^\n]+)", stdout or ""):
            credit_codes.append(m.group(1).strip())
        
        # Extract business status
        business_status = []
        for m in re.finditer(r"经营状态[：:]\s*([^\n]+)", stdout or ""):
            business_status.append(m.group(1).strip())
        
        # Extract company types
        company_types = []
        for m in re.finditer(r"公司类型[：:]\s*([^\n]+)", stdout or ""):
            company_types.append(m.group(1).strip())
        
        # Extract registration authorities
        registration_authorities = []
        for m in re.finditer(r"登记机关[：:]\s*([^\n]+)", stdout or ""):
            registration_authorities.append(m.group(1).strip())
        
        # Extract ICP information
        icp_sites = []
        for m in re.finditer(r"网站名称[：:]\s*([^\n]+)", stdout or ""):
            icp_sites.append(m.group(1).strip())
        
        icp_domains = []
        for m in re.finditer(r"域名[：:]\s*([^\n]+)", stdout or ""):
            icp_domains.append(m.group(1).strip())
        
        icp_licenses = []
        for m in re.finditer(r"ICP备案号[：:]\s*([^\n]+)", stdout or ""):
            icp_licenses.append(m.group(1).strip())
        
        # Extract app information
        app_names = []
        for m in re.finditer(r"应用名称[：:]\s*([^\n]+)", stdout or ""):
            app_names.append(m.group(1).strip())
        
        app_categories = []
        for m in re.finditer(r"应用分类[：:]\s*([^\n]+)", stdout or ""):
            app_categories.append(m.group(1).strip())
        
        app_versions = []
        for m in re.finditer(r"当前版本[：:]\s*([^\n]+)", stdout or ""):
            app_versions.append(m.group(1).strip())
        
        # Extract Weibo information
        weibo_names = []
        for m in re.finditer(r"微博昵称[：:]\s*([^\n]+)", stdout or ""):
            weibo_names.append(m.group(1).strip())
        
        weibo_links = []
        for m in re.finditer(r"微博链接[：:]\s*([^\n]+)", stdout or ""):
            weibo_links.append(m.group(1).strip())
        
        # Extract WeChat information
        wechat_names = []
        for m in re.finditer(r"公众号名称[：:]\s*([^\n]+)", stdout or ""):
            wechat_names.append(m.group(1).strip())
        
        wechat_ids = []
        for m in re.finditer(r"微信号[：:]\s*([^\n]+)", stdout or ""):
            wechat_ids.append(m.group(1).strip())
        
        # Extract WeChat Mini Program information
        wx_app_names = []
        for m in re.finditer(r"小程序名称[：:]\s*([^\n]+)", stdout or ""):
            wx_app_names.append(m.group(1).strip())
        
        wx_app_categories = []
        for m in re.finditer(r"小程序分类[：:]\s*([^\n]+)", stdout or ""):
            wx_app_categories.append(m.group(1).strip())
        
        # Extract copyright information
        copyright_names = []
        for m in re.finditer(r"软件名称[：:]\s*([^\n]+)", stdout or ""):
            copyright_names.append(m.group(1).strip())
        
        copyright_numbers = []
        for m in re.finditer(r"登记号[：:]\s*([^\n]+)", stdout or ""):
            copyright_numbers.append(m.group(1).strip())
        
        # Extract investment information
        investment_companies = []
        for m in re.finditer(r"投资公司[：:]\s*([^\n]+)", stdout or ""):
            investment_companies.append(m.group(1).strip())
        
        investment_ratios = []
        for m in re.finditer(r"投资比例[：:]\s*([^\n]+)", stdout or ""):
            investment_ratios.append(m.group(1).strip())
        
        # Extract subsidiary information
        subsidiary_companies = []
        for m in re.finditer(r"子公司[：:]\s*([^\n]+)", stdout or ""):
            subsidiary_companies.append(m.group(1).strip())
        
        # Extract supplier information
        supplier_companies = []
        for m in re.finditer(r"供应商[：:]\s*([^\n]+)", stdout or ""):
            supplier_companies.append(m.group(1).strip())
        
        parsed.update({
            "companies": companies,
            "company_ids": company_ids,
            "legal_representatives": legal_reps,
            "registration_capital": capital,
            "establishment_dates": dates,
            "business_scopes": scopes,
            "addresses": addresses,
            "phone_numbers": phones,
            "emails": emails,
            "websites": websites,
            "unified_social_credit_codes": credit_codes,
            "business_status": business_status,
            "company_types": company_types,
            "registration_authorities": registration_authorities,
            # ICP information
            "icp_sites": icp_sites,
            "icp_domains": icp_domains,
            "icp_licenses": icp_licenses,
            # App information
            "app_names": app_names,
            "app_categories": app_categories,
            "app_versions": app_versions,
            # Weibo information
            "weibo_names": weibo_names,
            "weibo_links": weibo_links,
            # WeChat information
            "wechat_names": wechat_names,
            "wechat_ids": wechat_ids,
            # WeChat Mini Program information
            "wx_app_names": wx_app_names,
            "wx_app_categories": wx_app_categories,
            # Copyright information
            "copyright_names": copyright_names,
            "copyright_numbers": copyright_numbers,
            # Investment information
            "investment_companies": investment_companies,
            "investment_ratios": investment_ratios,
            # Subsidiary information
            "subsidiary_companies": subsidiary_companies,
            # Supplier information
            "supplier_companies": supplier_companies
        })
    elif tool == "searchsploit":
        # Extract exploit IDs
        exploit_ids = []
        for m in re.finditer(r"(\d+)\s+\|\s+", stdout or ""):
            exploit_ids.append(m.group(1))
        
        # Extract titles
        titles = []
        for m in re.finditer(r"\|\s+([^\|]+)\s+\|\s+", stdout or ""):
            title = m.group(1).strip()
            if title and title not in titles:
                titles.append(title)
        
        # Extract paths
        paths = []
        for m in re.finditer(r"\|\s+([^\|]+)\s*$", stdout or "", re.MULTILINE):
            path = m.group(1).strip()
            if path and path not in paths:
                paths.append(path)
        
        # Extract CVE numbers
        cves = []
        for m in re.finditer(r"CVE[-_]?\d{4}[-_]?\d{4,}", stdout or "", re.IGNORECASE):
            cve = m.group(0).upper()
            if cve not in cves:
                cves.append(cve)
        
        # Extract platforms
        platforms = []
        for m in re.finditer(r"\|\s+(linux|windows|bsd|solaris|macos|aix|hp-ux|irix|netbsd|openbsd|freebsd|sco|novell|unix|multiple|hardware|cgi|webapps)\s+\|", stdout or "", re.IGNORECASE):
            platform = m.group(1).lower()
            if platform not in platforms:
                platforms.append(platform)
        
        # Extract types
        types = []
        for m in re.finditer(r"\|\s+(dos|local|remote|shellcode|webapps)\s+\|", stdout or "", re.IGNORECASE):
            type = m.group(1).lower()
            if type not in types:
                types.append(type)
        
        # Extract dates
        dates = []
        for m in re.finditer(r"\|\s+(\d{4}-\d{2}-\d{2})\s+\|", stdout or ""):
            date = m.group(1)
            if date not in dates:
                dates.append(date)
        
        # Extract authors
        authors = []
        for m in re.finditer(r"\|\s+([^\|]+)\s+\|\s+\d{4}-\d{2}-\d{2}", stdout or ""):
            author = m.group(1).strip()
            if author and author not in authors:
                authors.append(author)
        
        # Extract verified exploits
        verified = []
        for m in re.finditer(r"\|\s+(verified)\s+\|", stdout or "", re.IGNORECASE):
            verified.append(m.group(1).lower())
        
        # Extract application names
        applications = []
        for line in lines:
            for word in re.findall(r"\b([A-Za-z][A-Za-z0-9_\-\.]{2,})\b", line):
                if len(word) > 3 and word.lower() not in ["linux", "windows", "exploit", "shell", "code", "remote", "local", "dos", "web", "app", "server", "client", "service", "daemon", "version", "vulnerability"]:
                    if word not in applications:
                        applications.append(word)
        
        # Extract URLs
        urls = []
        for m in re.finditer(r"https?://[^\s]+", stdout or ""):
            urls.append(m.group(0))
        
        # Extract file paths
        file_paths = []
        for m in re.finditer(r"([/\\][a-zA-Z0-9_\-/\\\.]+\.(?:txt|py|pl|rb|c|cpp|sh|php|html|js|asp|jsp))", stdout or ""):
            file_path = m.group(1)
            if file_path not in file_paths:
                file_paths.append(file_path)
        
        # Extract CVE matches in descriptions
        cve_matches = []
        for line in lines:
            if re.search(r"CVE[-_]?\d{4}[-_]?\d{4,}", line, re.IGNORECASE):
                cve_matches.append(line.strip())
        
        # Extract exploit titles with keywords
        exploit_titles = []
        for line in lines:
            if re.search(r"\|\s+([^\|]+)\s+\|", line):
                title_match = re.search(r"\|\s+([^\|]+)\s+\|", line)
                if title_match:
                    title = title_match.group(1).strip()
                    if title and title not in exploit_titles:
                        exploit_titles.append(title)
        
        # Extract full exploit entries
        exploit_entries = []
        for line in lines:
            if re.search(r"\|\s+\d+\s+\|", line):
                exploit_entries.append(line.strip())
        
        parsed.update({
            "exploit_ids": exploit_ids,
            "titles": titles,
            "paths": paths,
            "cves": cves,
            "platforms": platforms,
            "types": types,
            "dates": dates,
            "authors": authors,
            "verified": verified,
            "applications": applications[:20],  # Limit to first 20 to avoid noise
            "urls": urls,
            "file_paths": file_paths,
            "cve_matches": cve_matches,
            "exploit_titles": exploit_titles,
            "exploit_entries": exploit_entries
        })
    elif tool == "githacker":
        # Extract URLs
        urls = []
        for m in re.finditer(r"https?://[^\s]+", stdout or ""):
            urls.append(m.group(0))
        
        # Extract file paths
        file_paths = []
        for m in re.finditer(r"([/\\][a-zA-Z0-9_\-/\\\.]+\.[a-zA-Z0-9_\-]+)", stdout or ""):
            file_path = m.group(1)
            if file_path not in file_paths:
                file_paths.append(file_path)
        
        # Extract repository information
        repo_info = []
        for line in lines:
            if re.search(r"(?i)(repository|repo|git|clone|pull|commit|branch|tag)", line):
                repo_info.append(line.strip())
        
        # Extract extracted files information
        extracted_files = []
        for line in lines:
            if re.search(r"(?i)(extract|restore|recover|download|save|write)", line):
                extracted_files.append(line.strip())
        
        # Extract error messages
        errors = []
        for line in lines:
            if re.search(r"(?i)(error|fail|exception|denied|not found|invalid)", line):
                errors.append(line.strip())
        
        # Extract success messages
        success = []
        for line in lines:
            if re.search(r"(?i)(success|complete|done|finished|extracted|restored)", line):
                success.append(line.strip())
        
        # Extract directory information
        directories = []
        for m in re.finditer(r"([a-zA-Z]:[\\/][^\s]+)", stdout or ""):
            directories.append(m.group(1))
        
        # Extract commit hashes
        commits = []
        for m in re.finditer(r"\b([0-9a-f]{7,40})\b", stdout or ""):
            commits.append(m.group(1))
        
        parsed.update({
            "urls": urls,
            "file_paths": file_paths,
            "repo_info": repo_info,
            "extracted_files": extracted_files,
            "errors": errors,
            "success": success,
            "directories": directories,
            "commits": commits
        })
    elif tool == "gowitness":
        # Extract URLs
        urls = []
        for m in re.finditer(r"https?://[^\s]+", stdout or ""):
            urls.append(m.group(0))
        
        # Extract screenshot file paths
        screenshots = []
        for m in re.finditer(r"([a-zA-Z]:[\\/][^\s]*\.(?:png|jpg|jpeg))", stdout or ""):
            screenshots.append(m.group(1))
        
        # Extract status codes
        status_codes = []
        for m in re.finditer(r"(?:status|code|response):\s*(\d{3})", stdout or "", re.IGNORECASE):
            status_code = int(m.group(1))
            if status_code not in status_codes:
                status_codes.append(status_code)
        
        # Extract page titles
        titles = []
        for m in re.finditer(r"(?:title|page):\s*([^\n\r]+)", stdout or "", re.IGNORECASE):
            titles.append(m.group(1).strip())
        
        # Extract error messages
        errors = []
        for line in lines:
            if re.search(r"(?i)(error|fail|exception|denied|not found|invalid|timeout)", line):
                errors.append(line.strip())
        
        # Extract success messages
        success = []
        for line in lines:
            if re.search(r"(?i)(success|complete|done|finished|captured|saved)", line):
                success.append(line.strip())
        
        # Extract timing information
        timing = []
        for m in re.finditer(r"(?:time|duration|elapsed):\s*([0-9.]+)\s*(?:s|sec|seconds|ms|milliseconds)", stdout or "", re.IGNORECASE):
            timing.append(m.group(1))
        
        # Extract browser information
        browser_info = []
        for line in lines:
            if re.search(r"(?i)(chrome|browser|webdriver|headless)", line):
                browser_info.append(line.strip())
        
        # Extract scan statistics
        stats = []
        for line in lines:
            if re.search(r"(?i)(total|count|scanned|processed|completed|failed|success)", line):
                stats.append(line.strip())
        
        parsed.update({
            "urls": urls,
            "screenshots": screenshots,
            "status_codes": status_codes,
            "titles": titles,
            "errors": errors,
            "success": success,
            "timing": timing,
            "browser_info": browser_info,
            "stats": stats
        })
    elif tool == "hydra":
        # Extract successful login attempts
        successful_logins = []
        for m in re.finditer(r"\[([\d\.]+)\]\s+\[([^\]]+)\]\s+login:\s+(\S+)\s+password:\s+(\S+)", stdout or ""):
            successful_logins.append({
                "host": m.group(1),
                "service": m.group(2),
                "username": m.group(3),
                "password": m.group(4)
            })
        
        # Extract failed login attempts
        failed_logins = []
        for line in lines:
            if re.search(r"(?i)(failed|invalid|denied|refused|incorrect)", line) and not re.search(r"(?i)(successful|success)", line):
                failed_logins.append(line.strip())
        
        # Extract error messages
        errors = []
        for line in lines:
            if re.search(r"(?i)(error|exception|fatal|fail)", line):
                errors.append(line.strip())
        
        # Extract progress information
        progress = []
        for m in re.finditer(r"\[ATTEMPT\]\s+target\s+(\S+)\s+-\s+login:\s+(\S+)\s+-\s+password:\s+(\S+)", stdout or ""):
            progress.append({
                "target": m.group(1),
                "username": m.group(2),
                "password": m.group(3)
            })
        
        # Extract statistics
        stats = []
        for line in lines:
            if re.search(r"(?i)(attempts|tries|progress|complete|finished|remaining)", line):
                stats.append(line.strip())
        
        # Extract timing information
        timing = []
        for m in re.finditer(r"(?:time|elapsed|duration):\s*([0-9.]+)\s*(?:s|sec|seconds|h|hr|hours|m|min|minutes)", stdout or "", re.IGNORECASE):
            timing.append(m.group(1))
        
        # Extract task information
        tasks = []
        for m in re.finditer(r"(?:tasks|threads|parallel):\s*(\d+)", stdout or "", re.IGNORECASE):
            tasks.append(m.group(1))
        
        # Extract service information
        services = []
        for m in re.finditer(r"(?:service|protocol):\s*(\S+)", stdout or "", re.IGNORECASE):
            services.append(m.group(1))
        
        # Extract target information
        targets = []
        for m in re.finditer(r"(?:target|host):\s*(\S+)", stdout or "", re.IGNORECASE):
            targets.append(m.group(1))
        
        parsed.update({
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "errors": errors,
            "progress": progress,
            "stats": stats,
            "timing": timing,
            "tasks": tasks,
            "services": services,
            "targets": targets
        })
    elif tool == "httpx":
        # Extract URLs
        urls = []
        for m in re.finditer(r"https?://[^\s\[\]]+", stdout or ""):
            urls.append(m.group(0))
        
        # Extract status codes
        status_codes = []
        for m in re.finditer(r"\[([0-9]{3})\]", stdout or ""):
            status_codes.append(int(m.group(1)))
        
        # Extract page titles
        titles = []
        for m in re.finditer(r"\[([^\[\]]+)\]", stdout or ""):
            # Skip status codes (numeric)
            if not re.match(r"^[0-9]{3}$", m.group(1)):
                titles.append(m.group(1))
        
        # Extract technologies
        technologies = []
        for line in lines:
            # Look for technology indicators in the output
            tech_keywords = [
                "nginx", "apache", "iis", "cloudflare", "express", "django", "rails", 
                "php", "asp", "jsp", "node", "python", "ruby", "java", "go", "docker",
                "kubernetes", "aws", "azure", "gcp", "jquery", "react", "vue", "angular",
                "bootstrap", "wordpress", "drupal", "joomla", "shopify", "magento"
            ]
            for tech in tech_keywords:
                if tech.lower() in line.lower() and tech not in technologies:
                    technologies.append(tech)
        
        # Extract content lengths
        content_lengths = []
        for m in re.finditer(r"length:\s*(\d+)", stdout or "", re.IGNORECASE):
            content_lengths.append(int(m.group(1)))
        
        # Extract IP addresses
        ips = []
        for m in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", stdout or ""):
            ips.append(m.group(0))
        
        # Extract JARM hashes
        jarm_hashes = []
        for m in re.finditer(r"jarm:\s*([a-f0-9]{62})", stdout or "", re.IGNORECASE):
            jarm_hashes.append(m.group(1))
        
        # Extract error messages
        errors = []
        for line in lines:
            if re.search(r"(?i)(error|fail|exception|denied|not found|invalid|timeout|connection refused)", line):
                errors.append(line.strip())
        
        # Extract redirect chains
        redirects = []
        for line in lines:
            if re.search(r"(?i)(redirect|location|moved)", line):
                redirects.append(line.strip())
        
        # Parse structured results
        results = []
        # Try to match the typical httpx output format: URL [STATUS_CODE] [TITLE]
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
                
            # Try to extract URL, status code, and title from each line
            url_match = re.search(r"(https?://[^\s\[\]]+)", line)
            status_match = re.search(r"\[([0-9]{3})\]", line)
            title_match = re.search(r"\[([^\[\]]+)\]", line)
            
            if url_match:
                result = {"url": url_match.group(0)}
                
                if status_match:
                    result["status_code"] = int(status_match.group(1))
                
                if title_match and not re.match(r"^[0-9]{3}$", title_match.group(1)):
                    result["title"] = title_match.group(1)
                
                # Extract IP if present
                ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
                if ip_match:
                    result["ip"] = ip_match.group(0)
                
                # Extract content length if present
                length_match = re.search(r"length:\s*(\d+)", line, re.IGNORECASE)
                if length_match:
                    result["content_length"] = int(length_match.group(1))
                
                # Extract technologies if present
                line_techs = []
                for tech in technologies:
                    if tech.lower() in line.lower():
                        line_techs.append(tech)
                if line_techs:
                    result["technologies"] = line_techs
                
                # Extract JARM if present
                jarm_match = re.search(r"jarm:\s*([a-f0-9]{62})", line, re.IGNORECASE)
                if jarm_match:
                    result["jarm"] = jarm_match.group(1)
                
                results.append(result)
        
        parsed.update({
            "results": results,
            "urls": urls,
            "status_codes": status_codes,
            "titles": titles,
            "technologies": technologies,
            "content_lengths": content_lengths,
            "ips": ips,
            "jarm_hashes": jarm_hashes,
            "errors": errors,
            "redirects": redirects,
            "format": "structured",
            "source": "stdout_parsing"
        })
    elif tool == "seclists":
        # SecLists主要是字典文件集合，不需要实际执行命令
        # 这里我们模拟解析SecLists的输出
        
        # 获取SecLists路径
        seclists_path = data.get("seclists_path", "D:\\Global\\apps\\SecLists\\current")
        
        # 检查SecLists路径是否存在
        path_exists = os.path.exists(seclists_path) if seclists_path else False
        
        # 获取复制到工作目录选项
        copy_to_workdir = data.get("copy_to_workdir", False)
        workdir_path = data.get("workdir_path", os.getcwd())
        
        # 获取内存传递选项
        return_content = data.get("return_content", False)
        max_lines = data.get("max_lines", 1000)  # 限制返回的行数，避免内存问题
        
        # 获取操作类型
        action = data.get("action", "list")
        
        # 获取分类和类型
        category = data.get("category", "")
        list_type = data.get("list_type", "")
        
        # 提取字典分类
        categories = []
        for line in lines:
            if re.search(r"(?i)(passwords|usernames|discovery|fuzzing|webshells|payloads)", line):
                categories.append(line.strip())
        
        # 如果没有从输出中提取到分类，尝试从SecLists路径中获取
        if not categories and path_exists:
            try:
                for item in os.listdir(seclists_path):
                    if os.path.isdir(os.path.join(seclists_path, item)):
                        if re.search(r"(?i)(passwords|usernames|discovery|fuzzing|webshells|payloads)", item):
                            categories.append(item)
            except Exception:
                pass
        
        # 提取字典文件路径
        file_paths = []
        for m in re.finditer(r"([/\\][a-zA-Z0-9_\-/\\\.]+\.(?:txt|lst|dic|wordlist))", stdout or ""):
            file_paths.append(m.group(1))
        
        # 如果没有从输出中提取到文件路径，尝试从SecLists路径中获取
        if not file_paths and path_exists:
            try:
                for root, dirs, files in os.walk(seclists_path):
                    for file in files:
                        if file.endswith(('.txt', '.lst', '.dic', '.wordlist')):
                            rel_path = os.path.relpath(os.path.join(root, file), seclists_path)
                            file_paths.append(rel_path)
                            # 限制返回的文件数量，避免过多
                            if len(file_paths) >= 50:
                                break
                    if len(file_paths) >= 50:
                        break
            except Exception:
                pass
        
        # 如果指定了分类和类型，尝试找到匹配的文件
        target_file = None
        if category and list_type and path_exists:
            try:
                # 构建可能的文件路径
                category_path = os.path.join(seclists_path, category)
                if os.path.exists(category_path):
                    for file in os.listdir(category_path):
                        if list_type.lower() in file.lower() and file.endswith(('.txt', '.lst', '.dic', '.wordlist')):
                            target_file = os.path.join(category_path, file)
                            break
            except Exception:
                pass
        
        # 如果需要复制到工作目录且找到了目标文件
        copied_files = []
        wordlist_content = None
        
        if copy_to_workdir and target_file and os.path.exists(target_file):
            try:
                # 确保工作目录存在
                os.makedirs(workdir_path, exist_ok=True)
                
                # 创建目标文件名
                filename = os.path.basename(target_file)
                dest_path = os.path.join(workdir_path, filename)
                
                # 复制文件
                import shutil
                shutil.copy2(target_file, dest_path)
                copied_files.append(dest_path)
                
                # 添加成功信息
                success = [f"文件已复制到工作目录: {dest_path}"]
            except Exception as e:
                errors = [f"复制文件失败: {str(e)}"]
        
        # 如果需要返回文件内容到内存
        if return_content and target_file and os.path.exists(target_file):
            try:
                with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # 限制返回的行数
                if len(lines) > max_lines:
                    wordlist_content = {
                        "content": lines[:max_lines],
                        "total_lines": len(lines),
                        "truncated": True,
                        "max_lines": max_lines
                    }
                    success.append(f"词汇表内容已读取到内存（共 {len(lines)} 行，已截断为前 {max_lines} 行）")
                else:
                    wordlist_content = {
                        "content": lines,
                        "total_lines": len(lines),
                        "truncated": False
                    }
                    success.append(f"词汇表内容已读取到内存（共 {len(lines)} 行）")
            except Exception as e:
                errors.append(f"读取文件内容失败: {str(e)}")
        
        # 提取字典文件大小
        file_sizes = []
        for m in re.finditer(r"size:\s*(\d+)\s*(?:kb|mb|gb|b)", stdout or "", re.IGNORECASE):
            file_sizes.append(m.group(1))
        
        # 如果没有从输出中提取到文件大小，尝试计算实际文件大小
        if not file_sizes and path_exists and file_paths:
            try:
                for file_path in file_paths[:10]:  # 只计算前10个文件的大小，避免过多操作
                    full_path = os.path.join(seclists_path, file_path)
                    if os.path.isfile(full_path):
                        size_bytes = os.path.getsize(full_path)
                        if size_bytes > 1024 * 1024:
                            size_str = f"{size_bytes // (1024 * 1024)}MB"
                        elif size_bytes > 1024:
                            size_str = f"{size_bytes // 1024}KB"
                        else:
                            size_str = f"{size_bytes}B"
                        file_sizes.append(size_str)
            except Exception:
                pass
        
        # 提取字典条目数量
        entry_counts = []
        for m in re.finditer(r"(?:entries|lines|words):\s*(\d+)", stdout or "", re.IGNORECASE):
            entry_counts.append(m.group(1))
        
        # 如果没有从输出中提取到条目数量，尝试计算实际文件行数
        if not entry_counts and path_exists and file_paths:
            try:
                for file_path in file_paths[:5]:  # 只计算前5个文件的行数，避免过多操作
                    full_path = os.path.join(seclists_path, file_path)
                    if os.path.isfile(full_path):
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines_count = sum(1 for _ in f)
                            entry_counts.append(str(lines_count))
            except Exception:
                pass
        
        # 提取字典类型
        list_types = []
        for line in lines:
            if re.search(r"(?i)(common|default|rockyou|top10k|top100k|top1million)", line):
                list_types.append(line.strip())
        
        # 提取使用建议
        usage_tips = []
        for line in lines:
            if re.search(r"(?i)(usage|example|recommend|suggest)", line):
                usage_tips.append(line.strip())
        
        # 如果没有使用建议，添加默认建议
        if not usage_tips:
            usage_tips = [
                "使用密码字典进行弱密码测试",
                "使用用户名字典进行用户名枚举",
                "使用发现字典进行目录和文件发现",
                "使用模糊测试字典进行参数模糊测试"
            ]
        
        # 提取错误信息
        errors = []
        for line in lines:
            if re.search(r"(?i)(error|fail|exception|not found|invalid)", line):
                errors.append(line.strip())
        
        # 检查路径是否存在，如果不存在添加错误信息
        if not path_exists and seclists_path:
            errors.append(f"SecLists路径不存在: {seclists_path}")
        
        # 提取成功信息
        success = []
        for line in lines:
            if re.search(r"(?i)(success|complete|done|found|loaded)", line):
                success.append(line.strip())
        
        # 如果路径存在，添加成功信息
        if path_exists:
            success.append(f"SecLists路径有效: {seclists_path}")
        
        # 构建解析结果
        result = {
            "seclists_path": seclists_path,
            "path_exists": path_exists,
            "categories": categories,
            "file_paths": file_paths,
            "file_sizes": file_sizes,
            "entry_counts": entry_counts,
            "list_types": list_types,
            "usage_tips": usage_tips,
            "errors": errors,
            "success": success,
            "format": "dictionary_info",
            "source": "stdout_parsing"
        }
        
        # 添加复制文件信息
        if copy_to_workdir:
            result["copy_to_workdir"] = True
            result["workdir_path"] = workdir_path
            if copied_files:
                result["copied_files"] = copied_files
            if target_file:
                result["target_file"] = target_file
        
        # 添加内存内容信息
        if return_content:
            result["return_content"] = True
            result["max_lines"] = max_lines
            if wordlist_content:
                result["wordlist_content"] = wordlist_content
        
        parsed.update(result)
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
        try:
            # Windows环境下使用更安全的命令分割方式
            if sys.platform == "win32":
                # Windows: 使用字符串直接执行，避免shlex.split的问题
                cmd = command
            else:
                # Unix-like系统: 使用shlex.split
                cmd = shlex.split(command)
            result = executor.run(cmd)
            return jsonify(result)
        except Exception as e:
            logging.error(f"Command execution error: {str(e)}")
            return jsonify({"ok": False, "error": f"Command execution failed: {str(e)}"}), 500

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
        parsed = parse_tool_output(tool, result.get("stdout", ""), result.get("stderr", ""), data)
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
        parsed = parse_tool_output(tool, result.get("stdout", ""), result.get("stderr", ""), data)
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