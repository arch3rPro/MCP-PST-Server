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
        """
        Nmap是一款强大的网络扫描和安全审计工具，用于发现网络中的主机、服务
        和潜在的安全漏洞。支持多种扫描技术和服务识别功能。
        """
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
        """
        HTTPX是一款快速且多功能的HTTP探测器，用于发现和分析Web服务器。
        支持技术指纹识别、状态码检测和多种输出格式，适合大规模目标探测。
        """
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
        """
        FFUF是一款快速的Web模糊测试工具，用于发现隐藏的目录、文件和参数。
        支持多种过滤条件和匹配规则，可高效进行Web资源发现和漏洞挖掘。
        """
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
        """
        Feroxbuster是一款快速、灵活的目录和文件扫描工具，专为Web应用安全测试设计。
        支持递归扫描、多种文件扩展名和并发控制，能够高效发现隐藏的Web资源。
        """
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
        """  
        Fscan是一款内网综合扫描工具，集成了端口扫描、服务识别、漏洞检测和密码爆破等功能。
        适用于内网环境下的信息收集和安全评估，支持多种扫描模式和高效并发。
        """
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
        user_agent: str = "",
        referer: str = "",
        headers: str = "",
        proxy: str = "",
        level: str = "1",
        risk: str = "1",
        threads: str = "1",
        dbms: str = "",
        technique: str = "",
        os: str = "",
        batch: bool = False,
        fresh_queries: bool = False,
        tamper: str = "",
        random_agent: bool = False,
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        SQLMap是一款自动化的SQL注入和数据库接管工具，能够检测和利用SQL注入漏洞。
        支持多种数据库系统和注入技术，并提供强大的数据提取功能。
        """
        post_data = {
            "url": url,
            "data": data,
            "cookie": cookie,
            "user_agent": user_agent,
            "referer": referer,
            "headers": headers,
            "proxy": proxy,
            "level": level,
            "risk": risk,
            "threads": threads,
            "dbms": dbms,
            "technique": technique,
            "os": os,
            "batch": "1" if batch else "",
            "fresh_queries": "1" if fresh_queries else "",
            "tamper": tamper,
            "random_agent": "1" if random_agent else "",
            "output_file": output_file,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/sqlmap", post_data)

    # 企业信息收集工具
    @mcp.tool()
    def ens_scan(
        keyword: str = "",
        company_id: str = "",
        input_file: str = "",
        is_pid: bool = False,
        scan_type: str = "aqc",
        field: str = "",
        invest: str = "",
        deep: int = 0,
        hold: bool = False,
        supplier: bool = False,
        branch: bool = False,
        is_branch: bool = False,
        branch_filter: str = "",
        out_dir: str = "outs",
        out_type: str = "xlsx",
        json: bool = False,
        no_merge: bool = False,
        is_show: bool = True,
        delay: int = 0,
        proxy: str = "",
        timeout: int = 1,
        debug: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """       
        ENScan是一款企业信息收集工具，专门用于获取企业工商信息、股权结构、投资关系等数据。
        支持多种查询方式和深度挖掘功能，适用于企业背景调查和商业情报收集。
        """
        post_data = {
            "keyword": keyword,
            "company_id": company_id,
            "input_file": input_file,
            "is_pid": "1" if is_pid else "",
            "scan_type": scan_type,
            "field": field,
            "invest": invest,
            "deep": str(deep),
            "hold": "1" if hold else "",
            "supplier": "1" if supplier else "",
            "branch": "1" if branch else "",
            "is_branch": "1" if is_branch else "",
            "branch_filter": branch_filter,
            "out_dir": out_dir,
            "out_type": out_type,
            "json": "1" if json else "",
            "no_merge": "1" if no_merge else "",
            "is_show": "1" if is_show else "",
            "delay": str(delay),
            "proxy": proxy,
            "timeout": str(timeout),
            "debug": "1" if debug else "",
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/enscan", post_data)

    @mcp.tool()
    def metasploit_console(msf_cmd: str = "", rc_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"msf_cmd": msf_cmd, "rc_file": rc_file, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/metasploit", data, timeout=900)

    @mcp.tool()
    def john_crack(hash_file: str, wordlist: str = "", format: str = "", mask: str = "", rules: bool = False, additional_args: str = "") -> Dict[str, Any]:
        data = {"hash_file": hash_file, "wordlist": wordlist, "format": format, "mask": mask, "rules": ("1" if rules else ""), "additional_args": additional_args}
        return pst_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def searchsploit_exploit(
        term: str = "",
        title: bool = False,
        path: bool = False,
        url: bool = False,
        port: bool = False,
        author: bool = False,
        platform: str = "",
        type: str = "",
        date: str = "",
        nmap: str = "",
        vulns: str = "",
        cve: str = "",
        cwe: str = "",
        cbb: str = "",
        msb: str = "",
        osvdb: str = "",
        bid: str = "",
        edb: str = "",
        github: str = "",
        exploitdb: str = "",
        packetstorm: str = "",
        zdi: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        SearchSploit是Exploit-DB的命令行搜索工具，可以快速查找已知的漏洞利用代码和安全公告。
        支持多种搜索方式和过滤选项，帮助安全研究人员快速定位相关的漏洞信息。
        """
        post_data = {
            "term": term,
            "title": "1" if title else "",
            "path": "1" if path else "",
            "url": "1" if url else "",
            "port": "1" if port else "",
            "author": "1" if author else "",
            "platform": platform,
            "type": type,
            "date": date,
            "nmap": nmap,
            "vulns": vulns,
            "cve": cve,
            "cwe": cwe,
            "cbb": cbb,
            "msb": msb,
            "osvdb": osvdb,
            "bid": bid,
            "edb": edb,
            "github": github,
            "exploitdb": exploitdb,
            "packetstorm": packetstorm,
            "zdi": zdi,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/searchsploit", post_data)

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

    @mcp.tool()
    def amass_scan(
        target: str = "",
        mode: str = "enum",
        passive: bool = False,
        active: bool = True,
        brute: bool = False,
        min_for_recursive: int = 1,
        max_dns_queries: int = 10000,
        timeout: int = 30,
        include_unresolvable: bool = False,
        output_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        OWASP Amass是一款强大的开源网络攻击面映射和资产发现工具，通过多种信息收集技术
        帮助安全研究人员发现目标组织的网络资产和潜在攻击面。
        """
        post_data = {
            "target": target,
            "mode": mode,
            "passive": "1" if passive else "",
            "active": "1" if active else "",
            "brute": "1" if brute else "",
            "min_for_recursive": str(min_for_recursive),
            "max_dns_queries": str(max_dns_queries),
            "timeout": str(timeout),
            "include_unresolvable": "1" if include_unresolvable else "",
            "output_file": output_file,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/amass", post_data)

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

    @mcp.prompt()
    def amass_scan_guide() -> str:
        """
        # Amass攻击面映射与资产发现指南

        ## 常用扫描场景

        ### 1. 基本子域名枚举
        ```python
        amass_scan(target="example.com")
        ```

        ### 2. 被动信息收集
        ```python
        amass_scan(
            target="example.com",
            passive=True,
            active=False
        )
        ```

        ### 3. 暴力破解子域名
        ```python
        amass_scan(
            target="example.com",
            brute=True,
            max_dns_queries=20000
        )
        ```

        ## 核心参数说明

        ### 基本参数
        - target (必需): 目标域名或组织名称
        - mode: 操作模式，默认为"enum"(枚举)

        ### 扫描选项
        - passive: 仅使用被动信息收集技术
        - active: 使用主动DNS查询技术
        - brute: 启用暴力破解子域名
        - min_for_recursive: 递归枚举的最小子域名数量
        - max_dns_queries: 最大DNS查询数量限制

        ### 输出选项
        - output_file: 结果输出文件路径
        - include_unresolvable: 包含无法解析的条目
        - timeout: 网络请求超时时间(秒)

        ## 注意事项

        1. Amass会使用多种数据源进行信息收集，可能需要较长时间
        2. 暴力破解模式会产生大量DNS查询，请谨慎使用
        3. 被动模式仅使用公开数据源，不会直接与目标系统交互
        4. 使用additional_args参数可添加更多高级功能
        """

    @mcp.tool()
    def githacker_git_leak(
        url: str,
        output: str = "githacker_output",
        threads: int = 10,
        additional_args: Optional[str] = None
    ) -> str:
        """
        使用GitHacker工具从泄露的.git仓库中恢复源代码
        """
        return client.execute_tool(
            "githacker",
            url=url,
            output=output,
            threads=threads,
            additional_args=additional_args
        )

    @mcp.tool()
    def gowitness_screenshot(
        scan_type: str = "single",
        url: str = "",
        file: str = "",
        cidr: str = "",
        nmap_file: str = "",
        nessus_file: str = "",
        threads: int = 10,
        timeout: int = 30,
        delay: int = 0,
        screenshot_path: str = "gowitness",
        screenshot_format: str = "png",
        chrome_path: str = "",
        chrome_proxy: str = "",
        chrome_user_agent: str = "",
        write_db: bool = False,
        write_csv: bool = False,
        write_jsonl: bool = False,
        screenshot_fullpage: bool = False,
        save_content: bool = False,
        additional_args: Optional[str] = None
    ) -> str:
        """
        使用GoWitness工具对Web界面进行截图，用于信息收集和泄露检测
        """
        return client.execute_tool(
            "gowitness",
            scan_type=scan_type,
            url=url,
            file=file,
            cidr=cidr,
            nmap_file=nmap_file,
            nessus_file=nessus_file,
            threads=threads,
            timeout=timeout,
            delay=delay,
            screenshot_path=screenshot_path,
            screenshot_format=screenshot_format,
            chrome_path=chrome_path,
            chrome_proxy=chrome_proxy,
            chrome_user_agent=chrome_user_agent,
            write_db=write_db,
            write_csv=write_csv,
            write_jsonl=write_jsonl,
            screenshot_fullpage=screenshot_fullpage,
            save_content=save_content,
            additional_args=additional_args
        )

    @mcp.prompt()
    def gowitness_screenshot_guide() -> str:
        """
        # GoWitness Web截图指南

        ## 常用截图场景

        ### 1. 单个URL截图
        ```python
        gowitness_screenshot(
            scan_type="single",
            url="https://example.com"
        )
        ```

        ### 2. 批量URL文件截图
        ```python
        gowitness_screenshot(
            scan_type="file",
            file="urls.txt",
            threads=20
        )
        ```

        ### 3. CIDR网段截图
        ```python
        gowitness_screenshot(
            scan_type="cidr",
            cidr="192.168.1.0/24",
            threads=30
        )
        ```

        ### 4. 基于Nmap扫描结果截图
        ```python
        gowitness_screenshot(
            scan_type="nmap",
            nmap_file="scan.xml",
            threads=15
        )
        ```

        ### 5. 基于Nessus扫描结果截图
        ```python
        gowitness_screenshot(
            scan_type="nessus",
            nessus_file="nessus.xml",
            threads=15
        )
        ```

        ## 核心参数说明

        ### 扫描类型
        - scan_type: 扫描类型，可选"single"、"file"、"cidr"、"nmap"、"nessus"

        ### 目标参数
        - url: 单个目标URL(single模式)
        - file: 包含URL列表的文件路径(file模式)
        - cidr: CIDR格式的网段(cidr模式)
        - nmap_file: Nmap扫描结果XML文件(nmap模式)
        - nessus_file: Nessus扫描结果XML文件(nessus模式)

        ### 性能控制
        - threads: 并发线程数(默认10)
        - timeout: 单个URL超时时间(秒，默认30)
        - delay: 请求间延迟(秒，默认0)

        ### 输出选项
        - screenshot_path: 截图保存目录(默认"gowitness")
        - screenshot_format: 截图格式，可选"png"、"jpg"(默认"png")
        - write_db: 是否写入SQLite数据库(默认False)
        - write_csv: 是否导出CSV格式(默认False)
        - write_jsonl: 是否导出JSONL格式(默认False)

        ### 浏览器选项
        - chrome_path: Chrome浏览器路径
        - chrome_proxy: 代理设置
        - chrome_user_agent: 自定义User-Agent
        - screenshot_fullpage: 是否全页截图(默认False)
        - save_content: 是否保存页面内容(默认False)

        ## 注意事项

        1. 批量截图时建议适当调整线程数，避免对目标造成过大压力
        2. 超时时间应根据目标响应速度合理设置
        3. 全页截图会消耗更多时间和资源
        4. 使用代理可以绕过IP限制
        5. 保存页面内容可用于后续分析
        6. 使用additional_args参数可添加更多高级功能
        """

    @mcp.prompt()
    def githacker_git_leak_guide() -> str:
        """
        # GitHacker Git泄露利用指南

        ## 常用场景

        ### 1. 基本Git泄露利用
        ```python
        githacker_git_leak(url="http://example.com/.git/")
        ```

        ### 2. 指定输出目录
        ```python
        githacker_git_leak(
            url="http://example.com/.git/",
            output="recovered_source"
        )
        ```

        ### 3. 调整线程数
        ```python
        githacker_git_leak(
            url="http://example.com/.git/",
            threads=20
        )
        ```

        ## 核心参数说明

        ### 基本参数
        - url: 目标URL（必须包含.git目录泄露）
        - output: 输出目录，用于存储恢复的源代码
        - threads: 下载线程数，提高恢复速度

        ### 高级选项
        - additional_args: 额外的命令行参数

        ## 注意事项

        1. 仅对已授权的安全测试使用
        2. 确保目标URL确实存在.git泄露
        3. 恢复的源代码可能包含敏感信息
        4. 使用additional_args参数可添加更多高级功能
        """

    @mcp.prompt()
    def ens_scan_guide() -> str:
        """
        # ENScan企业信息收集指南

        ## 常用扫描场景

        ### 1. 基本企业信息查询
        ```python
        ens_scan(keyword="腾讯")
        ```

        ### 2. 根据公司ID查询详细信息
        ```python
        ens_scan(
            company_id="12345678",
            scan_type="aqc",
            field="基本信息"
        )
        ```

        ### 3. 批量企业信息收集
        ```python
        ens_scan(
            input_file="companies.txt",
            out_dir="./results",
            out_type="xlsx"
        )
        ```

        ### 4. 投资关系深度分析
        ```python
        ens_scan(
            keyword="阿里巴巴",
            invest="50",
            deep="3",
            hold=True
        )
        ```

        ### 5. 供应链信息收集
        ```python
        ens_scan(
            keyword="华为",
            supplier=True,
            branch=True
        )
        ```

        ## 核心参数说明

        ### 基本参数
        - keyword: 公司名称/关键字
        - company_id: 公司ID
        - input_file: 批量查询文件路径
        - is_pid: 是否使用PID模式(默认为False)

        ### 查询选项
        - scan_type: 扫描类型，默认为"aqc"(爱企查)，可选"tianyancha"(天眼查)、"qichacha"(企查查)等
        - field: 信息字段，如"基本信息"、"投资关系"、"知识产权"等
        - invest: 投资比例筛选(0-100)，只显示投资比例大于等于该值的公司
        - deep: 深度层级，控制递归查询的深度(默认为0，不递归)
        - hold: 是否查询控股关系(默认为False)
        - supplier: 是否查询供应商信息(默认为False)
        - branch: 是否查询分支机构(默认为False)
        - is_branch: 是否仅查询分支机构(默认为False)
        - branch_filter: 分支机构过滤条件

        ### 输出选项
        - out_dir: 结果输出目录，默认为"outs"
        - out_type: 输出格式，默认为"xlsx"，可选"json"、"csv"等
        - json: 是否以JSON格式输出结果(默认为False)
        - no_merge: 是否不合并结果(默认为False)
        - is_show: 是否显示进度(默认为True)

        ### 高级选项
        - delay: 请求延迟时间(秒)，默认为0
        - proxy: 代理设置
        - timeout: 请求超时时间(秒)，默认为1
        - debug: 是否启用调试模式(默认为False)
        - additional_args: 额外的命令行参数

        ## 注意事项

        1. 企业信息收集可能需要较长时间，请耐心等待
        2. 批量查询时建议设置合理的输出目录
        3. 深度查询(deep>0)会产生大量请求，请谨慎使用
        4. 投资比例筛选可以帮助过滤掉小额投资关系
        5. 使用additional_args参数可添加更多高级功能
        6. 不同数据源可能提供不同类型的信息
        7. 查询结果包含多种企业信息类型，如基本信息、ICP备案、APP信息、微博、微信公众号等
        """

    @mcp.prompt()
    def searchsploit_exploit_guide() -> str:
        """
        # SearchSploit漏洞利用查询指南

        ## 常用查询场景

        ### 1. 基本漏洞搜索
        ```python
        searchsploit_exploit(term="apache")
        ```

        ### 2. 按CVE编号搜索
        ```python
        searchsploit_exploit(cve="CVE-2021-44228")
        ```

        ### 3. 按平台和类型过滤
        ```python
        searchsploit_exploit(
            term="wordpress",
            platform="linux",
            type="webapps"
        )
        ```

        ### 4. 按作者搜索
        ```python
        searchsploit_exploit(
            term="sql injection",
            author=True
        )
        ```

        ### 5. 按日期范围搜索
        ```python
        searchsploit_exploit(
            term="remote",
            date="2020-2023"
        )
        ```

        ## 核心参数说明

        ### 搜索参数
        - term: 搜索关键词，支持多种格式
        - cve: 按CVE编号搜索(如"CVE-2021-44228")
        - cwe: 按CWE编号搜索
        - platform: 按平台过滤(如"linux", "windows", "hardware")
        - type: 按类型过滤(如"webapps", "dos", "local", "remote")
        - date: 按日期范围过滤(如"2020", "2020-2023")
        - author: 显示作者信息
        - title: 仅显示标题
        - path: 显示文件路径
        - url: 显示相关URL
        - port: 显示相关端口信息

        ### 高级过滤
        - nmap: 基于Nmap扫描结果过滤
        - vulns: 基于漏洞扫描结果过滤
        - cbb: 基于CBB(Common Bugs and Booboos)过滤
        - msb: 基于Microsoft安全公告过滤
        - osvdb: 基于OSVDB过滤
        - bid: 基于Bugtraq ID过滤
        - edb: 基于Exploit-DB ID过滤
        - github: 基于GitHub链接过滤
        - exploitdb: 基于Exploit-DB内容过滤
        - packetstorm: 基于Packet Storm过滤
        - zdi: 基于Zero Day Initiative过滤

        ## 注意事项

        1. SearchSploit查询的是公开的漏洞利用代码，仅供学习和研究使用
        2. 使用漏洞利用代码前请确保已获得合法授权
        3. 搜索结果可能包含过时的或不准确的漏洞信息
        4. 使用additional_args参数可添加更多高级功能
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
        mcp.run(transport=transport_mode)


if __name__ == "__main__":
    main()