#!/usr/bin/env python3

# MCP 客户端（Windows PST）。将常见渗透工具封装为 MCP 工具，转发到 PST API Server。

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

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
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "-T4 -Pn") -> Dict[str, Any]:
        data = {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def httpx_probe(target: str = "", list_file: str = "", additional_args: str = "-status -title -tech-detect") -> Dict[str, Any]:
        data = {"target": target, "list_file": list_file, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/httpx", data)

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str, additional_args: str = "") -> Dict[str, Any]:
        data = {"url": url, "wordlist": wordlist, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/ffuf", data)

    @mcp.tool()
    def feroxbuster_scan(url: str, wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        data = {"url": url, "wordlist": wordlist, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/feroxbuster", data)

    # 内网综合扫描与爆破
    @mcp.tool()
    def fscan_network(target: str, additional_args: str = "") -> Dict[str, Any]:
        data = {"target": target, "additional_args": additional_args}
        return pst_client.safe_post("api/tools/fscan", data)

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
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "--batch") -> Dict[str, Any]:
        post_data = {"url": url, "data": data, "additional_args": additional_args}
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

    return mcp


def parse_args():
    parser = argparse.ArgumentParser(description="Run the Windows PST MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_PST_SERVER, help=f"PST API server URL (default: {DEFAULT_PST_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
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
    logger.info("Starting PST MCP server")
    mcp.run()


if __name__ == "__main__":
    main()