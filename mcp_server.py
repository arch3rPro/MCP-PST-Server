#!/usr/bin/env python3

# MCP 客户端（Windows PST）。将常见渗透工具封装为 MCP 工具，转发到 PST API Server。

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import uvicorn

from mcp.server.fastmcp import FastMCP

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 默认配置
DEFAULT_PST_SERVER = "http://localhost:5100"
DEFAULT_REQUEST_TIMEOUT = 300  # seconds

class PSTToolsClient:
    """Windows PST API Server 客户端"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized PST Tools Client connecting to {server_url}")

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if params is None:
            params = {}
        url = f"{self.server_url}/{endpoint}"
        try:
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        if json_data is None:
            json_data = {}
        url = f"{self.server_url}/{endpoint}"
        try:
            response = requests.post(url, json=json_data, timeout=timeout or self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command})

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")


def setup_mcp_server(pst_client: PSTToolsClient) -> FastMCP:
    mcp = FastMCP("pst-mcp")

    # 基础网络与目录枚举
    @mcp.tool()
    def nmap_scan(
        target: str, 
        scan_type: str = "-sV", 
        ports: str = "", 
        timing: str = "T4",
        ping_scan: str = "-Pn",
        os_detection: str = "",
        service_detection: str = "",
        script_scan: str = "",
        script_args: str = "",
        output_format: str = "",
        output_file: str = "",
        min_rate: str = "",
        max_rate: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        data = {
            "target": target, 
            "scan_type": scan_type, 
            "ports": ports, 
            "timing": timing,
            "ping_scan": ping_scan,
            "os_detection": os_detection,
            "service_detection": service_detection,
            "script_scan": script_scan,
            "script_args": script_args,
            "output_format": output_format,
            "output_file": output_file,
            "min_rate": min_rate,
            "max_rate": max_rate,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def httpx_probe(
        target: str = "",
        list_file: str = "",
        status_code: bool = True,
        title: bool = False,
        tech_detect: bool = False,
        silent: bool = False,
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        post_data = {
            "target": target,
            "list_file": list_file,
            "status_code": "1" if status_code else "",
            "title": "1" if title else "",
            "tech_detect": "1" if tech_detect else "",
            "silent": "1" if silent else "",
            "output_file": output_file,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/httpx", post_data)

    @mcp.tool()
    def ffuf_scan(
        url: str,
        wordlist: str,
        method: str = "GET",
        data: str = "",
        headers: str = "",
        extensions: str = "",
        match_status: str = "200,204,301,302,307,401,403,405,500",
        filter_status: str = "",
        filter_size: str = "",
        threads: str = "40",
        recursion: bool = False,
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        post_data = {
            "url": url,
            "wordlist": wordlist,
            "method": method,
            "data": data,
            "headers": headers,
            "extensions": extensions,
            "match_status": match_status,
            "filter_status": filter_status,
            "filter_size": filter_size,
            "threads": threads,
            "recursion": "1" if recursion else "",
            "output_file": output_file,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/ffuf", post_data)

    @mcp.tool()
    def feroxbuster_scan(
        url: str = "",
        extensions: str = "",
        methods: str = "",
        headers: str = "",
        cookies: str = "",
        status_codes: str = "",
        threads: str = "",
        no_recursion: bool = False,
        depth: str = "",
        wordlist: str = "",
        rate_limit: str = "",
        time_limit: str = "",
        silent: bool = False,
        json: bool = False,
        output: str = "",
        burp: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        post_data = {
            "url": url,
            "extensions": extensions,
            "methods": methods,
            "headers": headers,
            "cookies": cookies,
            "status_codes": status_codes,
            "threads": threads,
            "no_recursion": "1" if no_recursion else "",
            "depth": depth,
            "wordlist": wordlist,
            "rate_limit": rate_limit,
            "time_limit": time_limit,
            "silent": "1" if silent else "",
            "json": "1" if json else "",
            "output": output,
            "burp": "1" if burp else "",
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/feroxbuster", post_data)

    # 内网综合扫描与爆破
    @mcp.tool()
    def fscan_network(
        target: str,
        ports: str = "",
        username: str = "",
        password: str = "",
        scan_mode: str = "All",
        threads: str = "60",
        timeout: str = "3",
        url: str = "",
        proxy: str = "",
        output_file: str = "result.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        post_data = {
            "target": target,
            "ports": ports,
            "username": username,
            "password": password,
            "scan_mode": scan_mode,
            "threads": threads,
            "timeout": timeout,
            "url": url,
            "proxy": proxy,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/fscan", post_data)

    @mcp.tool()
    def hydra_attack(target: str, service: str, username: str = "", username_file: str = "", password: str = "", password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/hydra", data)

    # ProjectDiscovery 套件
    @mcp.tool()
    def subfinder_enum(domain: str = "", list_file: str = "", additional_args: str = "-all -silent") -> Dict[str, Any]:
        data = {"domain": domain, "list_file": list_file, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/subfinder", data)

    @mcp.tool()
    def dnsx_resolve(domain: str = "", list_file: str = "", additional_args: str = "-a -resp -silent") -> Dict[str, Any]:
        data = {"domain": domain, "list_file": list_file, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/dnsx", data)

    @mcp.tool()
    def naabu_scan(host: str = "", list_file: str = "", ports: str = "", additional_args: str = "-silent") -> Dict[str, Any]:
        data = {"host": host, "list_file": list_file, "ports": ports, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/naabu", data)

    @mcp.tool()
    def nuclei_scan(target: str = "", list_file: str = "", template: str = "", tags: str = "", severity: str = "", additional_args: str = "-silent") -> Dict[str, Any]:
        data = {"target": target, "list_file": list_file, "template": template, "tags": tags, "severity": severity, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/nuclei", data)

    @mcp.tool()
    def katana_crawl(url: str = "", list_file: str = "", depth: str = "3", additional_args: str = "-silent") -> Dict[str, Any]:
        data = {"url": url, "list_file": list_file, "depth": depth, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/katana", data)

    # 其他常用
    @mcp.tool()
    def afrog_scan(target: str = "", list_file: str = "", pocs: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"target": target, "list_file": list_file, "pocs": pocs, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/afrog", data)

    @mcp.tool()
    def ehole_fingerprint(target: str = "", list_file: str = "", fingerprints: str = "", output: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"target": target, "list_file": list_file, "fingerprints": fingerprints, "output": output, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/ehole", data)

    @mcp.tool()
    def hackbrowserdata_dump(browser: str = "", output_dir: str = "./hbdata_output", additional_args: str = "") -> Dict[str, Any]:
        data = {"browser": browser, "output_dir": output_dir, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/hackbrowserdata", data)

    @mcp.tool()
    def sqlmap_scan(
        url: str,
        data: str = "",
        cookie: str = "",
        headers: str = "",
        proxy: str = "",
        level: str = "1",
        risk: str = "1",
        dbms: str = "",
        technique: str = "BEUST",
        batch: bool = True,
        threads: str = "1",
        dbs: bool = False,
        tables: bool = False,
        columns: bool = False,
        dump: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        post_data = {
            "url": url,
            "data": data,
            "cookie": cookie,
            "headers": headers,
            "proxy": proxy,
            "level": level,
            "risk": risk,
            "dbms": dbms,
            "technique": technique,
            "batch": "1" if batch else "",
            "threads": threads,
            "dbs": "1" if dbs else "",
            "tables": "1" if tables else "",
            "columns": "1" if columns else "",
            "dump": "1" if dump else "",
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_console(msf_cmd: str = "", rc_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"msf_cmd": msf_cmd, "rc_file": rc_file, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/metasploit", data, timeout=900)

    @mcp.tool()
    def john_crack(hash_file: str, wordlist: str = "", format: str = "", mask: str = "", rules: bool = False, additional_args: str = "") -> Dict[str, Any]:
        data = {"hash_file": hash_file, "wordlist": wordlist, "format": format, "mask": mask, "rules": ("1" if rules else ""), "additional_args": additional_args}
        return pst_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def nikto_scan(target: str, port: str = "", ssl: bool = False, additional_args: str = "") -> Dict[str, Any]:
        data = {"target": target, "port": port, "ssl": ("1" if ssl else ""), "additional_args": additional_args}
        return pst_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def gobuster_scan(mode: str = "dir", url: str = "", domain: str = "", wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"mode": mode, "url": url, "domain": domain, "wordlist": wordlist, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def masscan_scan(target: str, ports: str = "", rate: str = "", iface: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"target": target, "ports": ports, "rate": rate, "iface": iface, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/masscan", data)

    @mcp.tool()
    def netcat_run(mode: str = "client", host: str = "", port: str = "", listen_port: str = "", binary: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"mode": mode, "host": host, "port": port, "listen_port": listen_port, "binary": binary, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/netcat", data)

    @mcp.tool()
    def bbot_scan(target: str = "", preset: str = "", modules: str = "", flags: str = "", output_modules: str = "", output_dir: str = "", whitelist: str = "", blacklist: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {
            "target": target,
            "preset": preset,
            "modules": modules,
            "flags": flags,
            "output_modules": output_modules,
            "output_dir": output_dir,
            "whitelist": whitelist,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/bbot", data)

    # 健康检查与通用命令
    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        return pst_client.check_health()

    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        return pst_client.execute_command(command)

    @mcp.tool()
    def pw_list_tools(branch: str = "main") -> Dict[str, Any]:
        return pst_client.safe_get("api/catalog/pentest_windows", {"branch": branch})

    @mcp.tool()
    def pst_installed_tools() -> Dict[str, Any]:
        return pst_client.safe_get("api/catalog/installed")

    # Nmap扫描提示词
    @mcp.prompt()
    def nmap_scan_guide() -> str:
        """
        # Nmap端口扫描指南

        ## 常用扫描场景

        ### 1. 基本扫描
        ```python
        nmap_scan(target="192.168.1.1")
        ```

        ### 2. 端口扫描
        ```python
        nmap_scan(target="192.168.1.1", ports="1-1000")
        ```

        ### 3. 服务识别
        ```python
        nmap_scan(target="192.168.1.1", scan_type="-sV")
        ```

        ## 核心参数说明

        - target (必需): 扫描目标(IP/域名/CIDR)
        - scan_type: 扫描类型("-sS"=SYN扫描, "-sV"=服务版本检测)
        - ports: 端口范围(如"1-1000"或"22,80,443")
        - timing: 时序模板("T0"最慢最隐蔽, "T5"最快最易检测)
        - script_scan: 脚本扫描("default"默认, "vuln"漏洞扫描)
        - output_format: 输出格式("-oN"文本, "-oX"XML)

        ## 注意事项

        1. 确保已获得扫描授权
        2. 激进扫描可能触发警报
        3. 使用additional_args参数可添加更多高级功能
        """

    # SQLMap注入测试提示词
    @mcp.prompt()
    def sqlmap_scan_guide() -> str:
        """
        # SQLMap SQL注入测试指南

        ## 常用扫描场景

        ### 1. 基本SQL注入检测
        ```python
        sqlmap_scan(url="http://example.com/page.php?id=1")
        ```

        ### 2. POST请求注入测试
        ```python
        sqlmap_scan(
            url="http://example.com/login.php",
            data="username=admin&password=123"
        )
        ```

        ### 3. 数据库枚举
        ```python
        sqlmap_scan(
            url="http://example.com/page.php?id=1",
            dbs=True,
            tables=True
        )
        ```

        ## 核心参数说明

        ### 目标与请求参数
        - url (必需): 目标URL
        - data: POST请求数据
        - cookie: HTTP Cookie
        - headers: 自定义HTTP头

        ### 检测与注入参数
        - level: 测试等级(1-5, 默认1)
        - risk: 风险等级(1-3, 默认1)
        - dbms: 指定数据库类型(mysql, oracle, postgresql等)

        ### 数据枚举参数
        - dbs: 枚举所有数据库
        - tables: 枚举数据库表
        - columns: 枚举表列
        - dump: 转储表数据

        ## 注意事项

        1. 仅在授权范围内使用SQLMap
        2. 高风险等级可能导致目标系统不稳定
        3. 数据转储操作可能产生大量数据
        4. 使用additional_args参数可添加更多高级功能
        """

    # FFUF Web模糊测试提示词
    @mcp.prompt()
    def ffuf_scan_guide() -> str:
        """
        # FFUF Web模糊测试指南

        ## 常用扫描场景

        ### 1. 基本目录发现
        ```python
        ffuf_scan(url="http://example.com/FUZZ", wordlist="/path/to/directory-wordlist.txt")
        ```

        ### 2. 虚拟主机发现
        ```python
        ffuf_scan(
            url="http://example.com",
            wordlist="/path/to/subdomains.txt",
            headers="Host: FUZZ.example.com"
        )
        ```

        ### 3. POST数据模糊测试
        ```python
        ffuf_scan(
            url="http://example.com/login.php",
            method="POST",
            data="username=admin&password=FUZZ",
            wordlist="/path/to/passwords.txt"
        )
        ```

        ## 核心参数说明

        ### 目标与请求参数
        - url (必需): 目标URL，使用FUZZ关键字标记模糊测试位置
        - wordlist (必需): 词表文件路径
        - method: HTTP请求方法(默认GET)
        - data: POST请求数据
        - headers: 自定义HTTP头
        - extensions: 文件扩展名，多个用逗号分隔

        ### 匹配与过滤条件
        - match_status: 匹配的HTTP状态码，多个用逗号分隔
        - filter_status: 过滤的HTTP状态码
        - filter_size: 过滤的响应大小

        ### 性能控制
        - threads: 并发线程数，默认为40

        ## 注意事项

        1. FUZZ关键字是ffuf的核心，必须在URL或请求数据中指定它作为模糊测试的位置
        2. 使用适当的匹配和过滤条件可以大大减少噪音，提高扫描效率
        3. 递归扫描可能会产生大量请求，请谨慎使用
        4. 使用additional_args参数可添加更多高级功能
        """

    # HTTPX HTTP探测提示词
    @mcp.prompt()
    def httpx_probe_guide() -> str:
        """
        # HTTPX HTTP探测指南

        ## 常用探测场景

        ### 1. 基本HTTP探测
        ```python
        httpx_probe(url="http://example.com")
        ```

        ### 2. 批量目标探测
        ```python
        httpx_probe(
            url="http://example.com",
            silent=True,
            output_file="results.txt"
        )
        ```

        ### 3. 技术指纹识别
        ```python
        httpx_probe(
            url="http://example.com",
            tech_detect=True,
            status_code=True,
            title=True
        )
        ```

        ## 核心参数说明

        ### 输入选项
        - url (必需): 目标URL或URL列表文件

        ### 探测选项
        - status_code: 显示HTTP状态码
        - title: 显示页面标题
        - tech_detect: 启用技术指纹识别

        ### 输出选项
        - silent: 静默模式，减少输出
        - output_file: 结果输出文件路径

        ## 注意事项

        1. HTTPX支持多种输入格式，包括单个URL、URL列表文件
        2. 技术指纹识别功能可以帮助识别目标使用的技术栈
        3. 使用additional_args参数可添加更多高级功能
        """

    @mcp.prompt()
    def feroxbuster_scan_guide() -> str:
        """
        # Feroxbuster目录扫描指南

        ## 常用扫描场景

        ### 1. 基本目录扫描
        ```python
        feroxbuster_scan(url="http://example.com", wordlist="/path/to/wordlist.txt")
        ```

        ### 2. 递归扫描指定深度
        ```python
        feroxbuster_scan(
            url="http://example.com",
            wordlist="/path/to/wordlist.txt",
            depth=2,
            extensions="php,html,txt"
        )
        ```

        ### 3. 使用多种文件扩展名
        ```python
        feroxbuster_scan(
            url="http://example.com",
            wordlist="/path/to/wordlist.txt",
            extensions="php,asp,aspx,jsp,html,txt"
        )
        ```

        ## 核心参数说明

        ### 基本参数
        - url (必需): 目标URL
        - wordlist: 词表文件路径

        ### 扫描控制
        - extensions: 文件扩展名，多个用逗号分隔
        - threads: 并发线程数
        - depth: 递归扫描深度
        - rate_limit: 每秒请求数限制
        - time_limit: 扫描时间限制

        ### 输出设置
        - output: 结果输出文件路径
        - json: 以JSON格式输出结果

        ### 扩展参数
        - additional_args: 额外的命令行参数

        ## 注意事项

        1. 递归扫描可能会产生大量请求，建议设置合理的深度限制
        2. 使用适当的线程数和速率限制可以避免触发目标防护机制
        3. 使用additional_args参数可添加更多高级功能
        """

    @mcp.prompt()
    def fscan_network_guide() -> str:
        """
        # Fscan网络扫描指南

        ## 常用扫描场景

        ### 1. 基本端口扫描
        ```python
        fscan_network(target="192.168.1.1/24")
        ```

        ### 2. 详细服务识别
        ```python
        fscan_network(
            target="192.168.1.1",
            ports="1-1000",
            scan_mode="Port"
        )
        ```

        ### 3. 扫描结果保存
        ```python
        fscan_network(
            target="192.168.1.1/24",
            output_file="scan_results.txt"
        )
        ```

        ## 核心参数说明

        ### 基本参数
        - target (必需): 目标IP地址、IP段或域名

        ### 扫描选项
        - ports: 端口范围，例如"1-1000"或"80,443,8080"
        - scan_mode: 扫描模式，默认为All

        ### 输出选项
        - output_file: 结果输出文件路径

        ### 扩展参数
        - additional_args: 额外的命令行参数

        ## 注意事项

        1. 端口扫描可能会被防火墙或入侵检测系统检测到
        2. 大规模扫描建议使用output_file参数保存结果
        3. 使用additional_args参数可添加更多高级功能
        """

    return mcp


def parse_args():
    parser = argparse.ArgumentParser(description="Run the Windows PST MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_PST_SERVER, help=f"PST API server URL (default: {DEFAULT_PST_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    # 新增参数
    parser.add_argument("--host", type=str, default="127.0.0.1", help="MCP server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="MCP server port (default: 8000)")
    parser.add_argument("--path", type=str, default="/mcp", help="MCP server access path (default: /mcp)")
    parser.add_argument("--transport", type=str, default="studio", choices=["studio", "sse", "http"], help="MCP server startup mode (default: studio)")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    pst_client = PSTToolsClient(args.server, args.timeout)

    health = pst_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to PST API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Connected to PST API server at {args.server}")
        logger.info(f"Server health status: {health.get('status')}")
        if not health.get("all_essential_tools_available", False):
            missing = [t for t, ok in health.get("tools_status", {}).items() if not ok]
            if missing:
                logger.warning(f"Missing tools: {', '.join(missing)}")

    mcp = setup_mcp_server(pst_client)
    logger.info(f"Starting PST MCP server in {args.transport} mode")

    transport_map = {
        "studio": "stdio",
        "sse": "sse",
        "http": "streamable-http"
    }
    transport_mode = transport_map.get(args.transport)

    if not transport_mode:
        logger.error(f"Invalid startup mode: {args.transport}")
        return

    if transport_mode == 'sse':
        app = mcp.sse_app()
        uvicorn.run(app, host=args.host, port=args.port)
    elif transport_mode == 'streamable-http':
        app = mcp.streamable_http_app()
        uvicorn.run(app, host=args.host, port=args.port)
    else:
        mcp.run(
            host=args.host,
            port=args.port,
            path=args.path,
            transport=transport_mode
        )


if __name__ == "__main__":
    main()