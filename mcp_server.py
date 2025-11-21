#!/usr/bin/env python3

# MCP 客户端（Windows PST）。将常见渗透工具封装为 MCP 工具，转发到 PST API Server。

import sys
import os
import argparse
import logging
import tempfile
import shutil
import time
import uuid
import traceback
import json
from typing import Dict, Any, Optional, List, Callable
from functools import wraps
import requests
import uvicorn

from mcp.server.fastmcp import FastMCP

# 日志配置
def setup_logging(debug: bool = False, log_file: Optional[str] = None):
    """设置日志配置"""
    level = logging.DEBUG if debug else logging.INFO
    
    # 创建格式化器
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )
    
    # 设置处理器
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # 配置根日志记录器
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=handlers,
        force=True
    )
    
    return logging.getLogger(__name__)

# 全局日志记录器
logger = logging.getLogger(__name__)

# 性能监控装饰器
def monitor_performance(func: Callable) -> Callable:
    """监控函数执行性能的装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        function_name = func.__name__
        
        try:
            logger.debug(f"开始执行函数: {function_name}")
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"函数 {function_name} 执行成功，耗时: {execution_time:.2f}秒")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"函数 {function_name} 执行失败，耗时: {execution_time:.2f}秒，错误: {str(e)}")
            logger.debug(f"函数 {function_name} 异常详情:\n{traceback.format_exc()}")
            raise
    return wrapper

# 错误处理装饰器
def handle_errors(error_message: str = "操作失败", return_on_error: Any = None, log_error: bool = True) -> Callable:
    """错误处理装饰器"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_error:
                    logger.error(f"{error_message}: {str(e)}")
                    logger.debug(f"异常详情:\n{traceback.format_exc()}")
                return return_on_error
        return wrapper
    return decorator

# 重试机制装饰器
def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0, exceptions: tuple = (Exception,)):
    """重试机制装饰器"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay
            
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        logger.error(f"函数 {func.__name__} 在 {max_attempts} 次尝试后仍然失败: {str(e)}")
                        raise
                    
                    logger.warning(f"函数 {func.__name__} 第 {attempt} 次尝试失败: {str(e)}，{current_delay}秒后重试")
                    time.sleep(current_delay)
                    current_delay *= backoff
        return wrapper
    return decorator

# 默认配置
DEFAULT_PST_SERVER = "http://localhost:5100"
DEFAULT_REQUEST_TIMEOUT = 300  # seconds


class TempFileManager:
    """临时文件管理器，用于跟踪和清理临时文件"""
    
    def __init__(self):
        self.temp_files = {}  # {file_id: {"path": path, "created_at": timestamp, "purpose": purpose}}
        self.temp_dirs = []    # 临时目录列表
        self._lock = False     # 简单的锁机制，防止并发操作
        logger.debug("初始化临时文件管理器")
    
    @monitor_performance
    @handle_errors("创建临时文件失败", None)
    def create_temp_file(self, content: str = "", suffix: str = ".txt", prefix: str = "mcp_") -> str:
        """创建临时文件并返回文件路径"""
        if self._lock:
            logger.warning("临时文件管理器正忙，请稍后再试")
            raise Exception("临时文件管理器正忙")
        
        try:
            temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, prefix=prefix)
            
            if content:
                temp_file.write(content)
            
            temp_file.close()
            
            file_id = str(uuid.uuid4())
            self.temp_files[file_id] = {
                "path": temp_file.name,
                "created_at": time.time(),
                "purpose": "general"
            }
            
            logger.info(f"创建临时文件成功: {temp_file.name} (ID: {file_id})")
            return temp_file.name
        except Exception as e:
            logger.error(f"创建临时文件失败: {str(e)}")
            raise
    
    @monitor_performance
    @handle_errors("创建指定ID的临时文件失败", None)
    def create_temp_file_with_id(self, file_id: str, content: str = "", suffix: str = ".txt", prefix: str = "mcp_") -> str:
        """创建带指定ID的临时文件"""
        if self._lock:
            logger.warning("临时文件管理器正忙，请稍后再试")
            raise Exception("临时文件管理器正忙")
        
        if file_id in self.temp_files:
            logger.warning(f"文件ID {file_id} 已存在，将覆盖原有文件")
            self.delete_temp_file(file_id)
        
        try:
            temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=suffix, prefix=prefix)
            
            if content:
                temp_file.write(content)
            
            temp_file.close()
            
            self.temp_files[file_id] = {
                "path": temp_file.name,
                "created_at": time.time(),
                "purpose": "general"
            }
            
            logger.info(f"创建带ID的临时文件成功: {file_id} -> {temp_file.name}")
            return temp_file.name
        except Exception as e:
            logger.error(f"创建带ID的临时文件失败: {str(e)}")
            raise
    
    @handle_errors("获取临时文件路径失败", None)
    def get_temp_file_path(self, file_id: str) -> Optional[str]:
        """根据ID获取临时文件路径"""
        if file_id in self.temp_files:
            return self.temp_files[file_id]["path"]
        logger.warning(f"未找到ID为 {file_id} 的临时文件")
        return None
    
    @monitor_performance
    @handle_errors("删除临时文件失败", False)
    def delete_temp_file(self, file_id: str) -> bool:
        """根据ID删除临时文件"""
        if file_id not in self.temp_files:
            logger.warning(f"尝试删除不存在的临时文件ID: {file_id}")
            return False
            
        file_path = self.temp_files[file_id]["path"]
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
                logger.info(f"删除临时文件成功: {file_path} (ID: {file_id})")
            else:
                logger.warning(f"尝试删除不存在的临时文件: {file_path}")
            
            del self.temp_files[file_id]
            return True
        except Exception as e:
            logger.error(f"删除临时文件失败 {file_path}: {str(e)}")
            return False
    
    @monitor_performance
    @handle_errors("根据路径删除临时文件失败", False)
    def delete_temp_file_by_path(self, file_path: str) -> bool:
        """根据路径删除临时文件"""
        for file_id, file_info in list(self.temp_files.items()):
            if file_info["path"] == file_path:
                return self.delete_temp_file(file_id)
        
        # 如果不在跟踪列表中，尝试直接删除
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
                logger.info(f"删除未跟踪的临时文件成功: {file_path}")
                return True
            else:
                logger.warning(f"尝试删除不存在的未跟踪临时文件: {file_path}")
        except Exception as e:
            logger.error(f"删除未跟踪的临时文件失败 {file_path}: {str(e)}")
        
        return False
    
    @monitor_performance
    @handle_errors("创建临时目录失败", "")
    def create_temp_dir(self, prefix: str = "mcp_") -> str:
        """创建临时目录"""
        try:
            temp_dir = tempfile.mkdtemp(prefix=prefix)
            self.temp_dirs.append(temp_dir)
            logger.info(f"创建临时目录成功: {temp_dir}")
            return temp_dir
        except Exception as e:
            logger.error(f"创建临时目录失败: {str(e)}")
            raise
    
    @monitor_performance
    @handle_errors("清理临时文件失败", 0)
    def cleanup_temp_files(self, max_age_hours: float = 24.0) -> int:
        """清理超过指定时间的临时文件"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        deleted_count = 0
        
        logger.info(f"开始清理超过 {max_age_hours} 小时的临时文件")
        
        # 清理临时文件
        for file_id, file_info in list(self.temp_files.items()):
            age_seconds = current_time - file_info["created_at"]
            if age_seconds > max_age_seconds:
                if self.delete_temp_file(file_id):
                    deleted_count += 1
        
        # 清理临时目录
        for temp_dir in self.temp_dirs[:]:
            try:
                dir_stat = os.stat(temp_dir)
                age_seconds = current_time - dir_stat.st_mtime
                if age_seconds > max_age_seconds:
                    shutil.rmtree(temp_dir)
                    self.temp_dirs.remove(temp_dir)
                    logger.info(f"删除临时目录成功: {temp_dir}")
                    deleted_count += 1
            except Exception as e:
                logger.error(f"删除临时目录失败 {temp_dir}: {str(e)}")
        
        logger.info(f"清理完成，共删除 {deleted_count} 个超过 {max_age_hours} 小时的临时项目")
        return deleted_count
    
    @monitor_performance
    @handle_errors("清理所有临时文件失败", 0)
    def cleanup_all_temp_files(self) -> int:
        """清理所有临时文件和目录"""
        deleted_count = 0
        
        logger.info("开始清理所有临时文件和目录")
        
        # 清理所有临时文件
        for file_id in list(self.temp_files.keys()):
            if self.delete_temp_file(file_id):
                deleted_count += 1
        
        # 清理所有临时目录
        for temp_dir in self.temp_dirs[:]:
            try:
                shutil.rmtree(temp_dir)
                self.temp_dirs.remove(temp_dir)
                logger.info(f"删除临时目录成功: {temp_dir}")
                deleted_count += 1
            except Exception as e:
                logger.error(f"删除临时目录失败 {temp_dir}: {str(e)}")
        
        logger.info(f"清理完成，共删除 {deleted_count} 个临时项目")
        return deleted_count
    
    @handle_errors("列出临时文件失败", {})
    def list_temp_files(self) -> Dict[str, Dict[str, Any]]:
        """列出所有临时文件信息"""
        result = {}
        try:
            for file_id, file_info in self.temp_files.items():
                file_exists = os.path.exists(file_info["path"])
                file_size = 0
                
                if file_exists:
                    try:
                        file_size = os.path.getsize(file_info["path"])
                    except Exception:
                        pass
                
                result[file_id] = {
                    "path": file_info["path"],
                    "created_at": file_info["created_at"],
                    "age_hours": (time.time() - file_info["created_at"]) / 3600,
                    "purpose": file_info["purpose"],
                    "exists": file_exists,
                    "size_bytes": file_size
                }
        except Exception as e:
            logger.error(f"列出临时文件失败: {str(e)}")
            raise
        
        return result
    
    @handle_errors("获取临时文件统计信息失败", {})
    def get_temp_file_stats(self) -> Dict[str, Any]:
        """获取临时文件统计信息"""
        total_files = len(self.temp_files)
        total_dirs = len(self.temp_dirs)
        total_size = 0
        existing_files = 0
        
        try:
            for file_info in self.temp_files.values():
                try:
                    if os.path.exists(file_info["path"]):
                        total_size += os.path.getsize(file_info["path"])
                        existing_files += 1
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"计算临时文件大小失败: {str(e)}")
        
        return {
            "total_files": total_files,
            "existing_files": existing_files,
            "total_directories": total_dirs,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        }


# 全局临时文件管理器实例
# 确保在所有装饰器和依赖项定义后正确初始化
global_temp_file_manager = None

def init_temp_file_manager():
    """初始化临时文件管理器"""
    global global_temp_file_manager
    if global_temp_file_manager is None:
        global_temp_file_manager = TempFileManager()
        logger.info("临时文件管理器初始化成功")
    return global_temp_file_manager

# 立即初始化临时文件管理器
global_temp_file_manager = init_temp_file_manager()

class PSTToolsClient:
    """Windows PST API Server 客户端"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "MCP-PST-Client/1.0"
        })
        logger.info(f"初始化PST工具客户端，连接到: {server_url}")

    @monitor_performance
    @retry(max_attempts=3, delay=1.0, backoff=2.0, exceptions=(requests.exceptions.ConnectionError, requests.exceptions.Timeout))
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """安全的GET请求，带有重试机制"""
        if params is None:
            params = {}
        url = f"{self.server_url}/{endpoint}"
        
        logger.debug(f"发送GET请求到: {url}，参数: {params}")
        
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            # 尝试解析JSON响应
            try:
                result = response.json()
                logger.debug(f"GET请求成功，响应状态: {response.status_code}")
                return result
            except json.JSONDecodeError as e:
                logger.error(f"解析JSON响应失败: {str(e)}")
                return {
                    "error": f"解析JSON响应失败: {str(e)}", 
                    "success": False,
                    "response_text": response.text[:500]  # 只返回前500个字符
                }
        except requests.exceptions.RequestException as e:
            logger.error(f"GET请求失败: {str(e)}")
            return {"error": f"GET请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"GET请求发生意外错误: {str(e)}")
            return {"error": f"GET请求发生意外错误: {str(e)}", "success": False}

    @monitor_performance
    @retry(max_attempts=3, delay=1.0, backoff=2.0, exceptions=(requests.exceptions.ConnectionError, requests.exceptions.Timeout))
    def safe_post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
        """安全的POST请求，带有重试机制"""
        if json_data is None:
            json_data = {}
        url = f"{self.server_url}/{endpoint}"
        
        logger.debug(f"发送POST请求到: {url}，数据: {json_data}")
        
        try:
            response = self.session.post(url, json=json_data, timeout=timeout or self.timeout)
            response.raise_for_status()
            
            # 尝试解析JSON响应
            try:
                result = response.json()
                logger.debug(f"POST请求成功，响应状态: {response.status_code}")
                return result
            except json.JSONDecodeError as e:
                logger.error(f"解析JSON响应失败: {str(e)}")
                return {
                    "error": f"解析JSON响应失败: {str(e)}", 
                    "success": False,
                    "response_text": response.text[:500]  # 只返回前500个字符
                }
        except requests.exceptions.RequestException as e:
            logger.error(f"POST请求失败: {str(e)}")
            return {"error": f"POST请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"POST请求发生意外错误: {str(e)}")
            return {"error": f"POST请求发生意外错误: {str(e)}", "success": False}

    @monitor_performance
    @handle_errors("执行命令失败", {"error": "命令执行失败", "success": False})
    def execute_command(self, command: str) -> Dict[str, Any]:
        """执行命令"""
        logger.info(f"执行命令: {command}")
        return self.safe_post("api/command", {"command": command})

    @monitor_performance
    @handle_errors("健康检查失败", {"error": "健康检查失败", "success": False})
    def check_health(self) -> Dict[str, Any]:
        """检查服务器健康状态"""
        logger.debug("执行健康检查")
        return self.safe_get("health")
    
    @monitor_performance
    def close(self):
        """关闭客户端会话"""
        try:
            self.session.close()
            logger.info("PST工具客户端会话已关闭")
        except Exception as e:
            logger.error(f"关闭客户端会话失败: {str(e)}")


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
        快速的Web模糊测试工具，用于发现隐藏的目录、文件和参数。
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
        additional_args: str = "",
        seclists_path: str = "D:\\Global\\apps\\SecLists\\current"
    ) -> Dict[str, Any]:
        """
        快速、灵活的目录和文件扫描工具，专为Web应用安全测试设计。
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
            "additional_args": additional_args,
            "seclists_path": seclists_path
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
    def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        port: str = "",
        tasks: str = "",
        wait_time: str = "",
        timeout: str = "",
        login_attempts: str = "",
        retry_time: str = "",
        exit_on_success: bool = False,
        skip_default_passwords: bool = False,
        skip_empty_passwords: bool = False,
        skip_login: bool = False,
        use_ssl: bool = False,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        THC Hydra是一款强大的密码爆破工具，支持多种协议和服务。
        可以对SSH、FTP、HTTP、RDP等多种服务进行用户名和密码的暴力破解。
        支持并行任务处理和多种攻击模式，是渗透测试中常用的密码破解工具。
        """
        post_data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "port": port,
            "tasks": tasks,
            "wait_time": wait_time,
            "timeout": timeout,
            "login_attempts": login_attempts,
            "retry_time": retry_time,
            "exit_on_success": "1" if exit_on_success else "",
            "skip_default_passwords": "1" if skip_default_passwords else "",
            "skip_empty_passwords": "1" if skip_empty_passwords else "",
            "skip_login": "1" if skip_login else "",
            "use_ssl": "1" if use_ssl else "",
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/hydra", post_data)

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
        自动化的SQL注入和数据库接管工具，能够检测和利用SQL注入漏洞。
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
    def seclists_wordlist(
        action: str = "list",
        category: str = "",
        list_type: str = "",
        output_file: str = "",
        seclists_path: str = "D:\\Global\\apps\\SecLists\\current",
        copy_to_workdir: bool = False,
        workdir_path: str = "",
        return_content: bool = False,
        max_lines: int = 1000,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        安全测试领域最全面的字典文件集合，为其他爆破和扫描工具提供各种类型的字典文件。
        """
        post_data = {
            "action": action,
            "category": category,
            "list_type": list_type,
            "output_file": output_file,
            "seclists_path": seclists_path,
            "copy_to_workdir": copy_to_workdir,
            "workdir_path": workdir_path,
            "return_content": return_content,
            "max_lines": max_lines,
            "additional_args": additional_args
        }
        return pst_client.safe_post("api/tools/seclists", post_data)

    @mcp.tool()
    def gobuster_scan(
        mode: str = "dir",
        url: str = "",
        domain: str = "",
        wordlist: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
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
    def seclists_wordlist_guide() -> str:
        """
        # SecLists字典文件使用指南

        ## 常用字典场景

        ### 1. 查看可用字典分类
        ```python
        seclists_wordlist(action="list")
        ```

        ### 2. 获取密码字典
        ```python
        seclists_wordlist(action="list", category="passwords", list_type="common")
        ```

        ### 3. 获取用户名字典
        ```python
        seclists_wordlist(action="list", category="usernames", list_type="common")
        ```

        ### 4. 获取Web内容发现字典
        ```python
        seclists_wordlist(action="list", category="discovery", list_type="web-content")
        ```

        ### 5. 获取模糊测试字典
        ```python
        seclists_wordlist(action="list", category="fuzzing", list_type="common")
        ```

        ### 6. 使用自定义SecLists路径
        ```python
        seclists_wordlist(action="list", seclists_path="C:\\CustomPath\\SecLists")
        ```

        ### 7. 复制字典文件到工作目录
        ```python
        # 复制密码字典到当前工作目录，便于其他工具使用
        seclists_wordlist(
            action="list", 
            category="passwords", 
            list_type="common",
            copy_to_workdir=True
        )
        ```

        ### 8. 复制字典文件到指定工作目录
        ```python
        # 复制字典文件到指定目录，便于FFUF等工具使用
        seclists_wordlist(
            action="list", 
            category="discovery", 
            list_type="web-content",
            copy_to_workdir=True,
            workdir_path="D:\\Code\\MCP-PST-Server"
        )
        ```

        ## 核心参数说明

        ### 基本参数
        - action: 操作类型，默认为"list"（列出可用字典）
        - category: 字典分类，如passwords、usernames、discovery、fuzzing等
        - list_type: 字典类型，如common、default、top10k等
        - output_file: 输出文件路径（可选）
        - seclists_path: SecLists安装路径，默认为"D:\\Global\\apps\\SecLists\\current"
        - additional_args: 额外的命令行参数

        ### 文件复制参数
        - copy_to_workdir: 是否将字典文件复制到工作目录（默认为False）
        - workdir_path: 工作目录路径（默认为当前工作目录）

        ## 字典分类说明

        ### Passwords（密码字典）
        - common: 常见密码
        - rockyou: RockYou泄露密码
        - top10k/top100k/top1million: 按频率排序的密码

        ### Usernames（用户名字典）
        - common: 常见用户名
        - names: 基于姓名的用户名

        ### Discovery（发现字典）
        - web-content: Web内容发现（目录、文件）
        - dns: DNS子域名发现
        - api: API端点发现

        ### Fuzzing（模糊测试字典）
        - common: 通用模糊测试载荷
        - web: Web应用模糊测试
        - xss: XSS测试载荷
        - sqli: SQL注入测试载荷

        ## 路径配置

        ### 默认路径
        系统默认使用"D:\\Global\\apps\\SecLists\\current"作为SecLists的安装路径。

        ### 自定义路径
        如果SecLists安装在其他位置，可以通过seclists_path参数指定：
        ```python
        seclists_wordlist(action="list", seclists_path="C:\\Tools\\SecLists")
        ```

        ### 路径验证
        系统会自动验证指定路径是否存在，如果路径不存在，将在结果中返回错误信息。

        ## 文件复制功能

        ### 复制到工作目录
        当设置copy_to_workdir=True时，工具会将选定的字典文件复制到工作目录，便于其他工具使用。
        这解决了SecLists工具与FFUF等工具之间的文件路径同步问题。

        ### 工作目录设置
        默认使用当前工作目录，也可以通过workdir_path参数指定自定义工作目录。

        ### 使用场景
        1. SecLists生成词汇表文件
        2. 自动复制到工作目录
        3. FFUF等工具直接使用复制后的文件
        4. 避免路径不一致问题

        ## 内存传递功能

        ### 内存中获取字典内容
        当设置return_content=True时，系统会将字典文件内容直接返回到内存中，
        避免文件路径问题，特别适合自动化工具链集成。

        ### 内容限制
        - 默认返回前1000行内容
        - 可通过max_lines参数自定义返回行数
        - 超过限制时会被截断并提示

        ### 使用场景
        - 与其他工具的无缝集成
        - 快速字典内容预览
        - 自动化脚本中的字典处理
        - 避免文件系统依赖

        ## 工具链集成示例

        ### SecLists与FFUF集成（文件复制方式）
        ```python
        # 1. 获取并复制字典文件
        result = seclists_wordlist(
            action="list", 
            category="discovery", 
            list_type="web-content",
            copy_to_workdir=True
        )
        
        # 2. 使用复制的字典文件进行FFUF扫描
        if result.get("copied_files"):
            wordlist_path = result["copied_files"][0]
            ffuf_scan(
                url="http://example.com/FUZZ",
                wordlist=wordlist_path
            )
        ```

        ### SecLists与FFUF集成（内存传递方式）
        ```python
        # 1. 在内存中获取字典内容
        result = seclists_wordlist(
            action="list", 
            category="discovery", 
            list_type="web-content",
            return_content=True,
            max_lines=5000
        )
        
        # 2. 将内容写入临时文件供FFUF使用
        if result.get("wordlist_content"):
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(result["wordlist_content"])
                temp_file = f.name
            
            # 3. 使用临时文件进行FFUF扫描
            ffuf_scan(
                url="http://example.com/FUZZ",
                wordlist=temp_file
            )
            
            # 4. 扫描完成后清理临时文件
            import os
            os.unlink(temp_file)
        ```

        ## 注意事项

        1. SecLists主要为其他工具提供字典文件，本身不执行扫描
        2. 字典文件通常较大，建议根据需要选择特定类型
        3. 使用字典文件进行爆破时请确保已获得合法授权
        4. 如果默认路径不存在，请使用seclists_path参数指定正确的安装路径
        5. 使用copy_to_workdir=True可以解决与其他工具的文件路径同步问题
        6. 复制的文件会保留原始文件名，如果目标目录已存在同名文件，将被覆盖
        7. 使用return_content=True时，注意内存使用情况，特别是对于大型字典文件
        8. 内存传递功能适合自动化工具链，可以避免文件系统依赖
        9. 使用additional_args参数可添加更多高级功能
        """

    @mcp.prompt()
    def gobuster_scan_guide() -> str:
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

    @mcp.tool()
    def wordlist_integration_workflow(
        target_url: str,
        scan_type: str = "directory",
        wordlist_category: str = "discovery",
        wordlist_type: str = "web-content",
        use_memory: bool = False,
        max_lines: int = 1000,
        workdir_path: str = "",
        scan_options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        工具链集成流程：SecLists生成→路径验证→工具扫描→结果分析
        """
        if scan_options is None:
            scan_options = {}
            
        # 步骤1: 生成或获取字典
        wordlist_result = {}
        
        if use_memory:
            # 内存传递方式
            wordlist_result = seclists_wordlist(
                action="list",
                category=wordlist_category,
                list_type=wordlist_type,
                return_content=True,
                max_lines=max_lines
            )
            
            # 检查是否成功获取字典内容
            if not wordlist_result.get("success") or not wordlist_result.get("wordlist_content"):
                return {
                    "success": False,
                    "error": "Failed to retrieve wordlist content",
                    "wordlist_result": wordlist_result
                }
                
            # 使用临时文件管理器创建临时文件
            file_id = f"wordlist_{scan_type}_{int(time.time())}"
            wordlist_path = global_temp_file_manager.create_temp_file_with_id(
                file_id=file_id,
                content=wordlist_result["wordlist_content"],
                suffix=".txt",
                prefix=f"wordlist_{scan_type}_"
            )
            
            # 更新wordlist_result以包含临时文件信息
            wordlist_result["temp_file_id"] = file_id
            wordlist_result["temp_file_path"] = wordlist_path
            
        else:
            # 文件复制方式
            wordlist_result = seclists_wordlist(
                action="list",
                category=wordlist_category,
                list_type=wordlist_type,
                copy_to_workdir=True,
                workdir_path=workdir_path if workdir_path else os.getcwd()
            )
            
            # 检查是否成功复制文件
            if not wordlist_result.get("success") or not wordlist_result.get("copied_files"):
                return {
                    "success": False,
                    "error": "Failed to copy wordlist file",
                    "wordlist_result": wordlist_result
                }
                
            wordlist_path = wordlist_result["copied_files"][0]
        
        # 步骤2: 验证字典文件路径
        if not os.path.exists(wordlist_path):
            return {
                "success": False,
                "error": f"Wordlist file not found at path: {wordlist_path}",
                "wordlist_result": wordlist_result
            }
        
        # 步骤3: 执行扫描
        scan_result = {}
        
        if scan_type == "directory":
            # 目录扫描
            scan_result = ffuf_scan(
                url=target_url,
                wordlist=wordlist_path,
                **scan_options
            )
        elif scan_type == "subdomain":
            # 子域名扫描
            scan_result = subfinder_enum(
                domain=target_url.replace("http://", "").replace("https://", "").split("/")[0],
                **scan_options
            )
        elif scan_type == "vhost":
            # 虚拟主机扫描
            scan_result = ffuf_scan(
                url=target_url,
                wordlist=wordlist_path,
                headers="Host: FUZZ",
                **scan_options
            )
        else:
            # 默认使用目录扫描
            scan_result = ffuf_scan(
                url=target_url,
                wordlist=wordlist_path,
                **scan_options
            )
        
        # 步骤4: 清理临时文件（如果是内存传递方式）
        if use_memory and wordlist_result.get("temp_file_id"):
            try:
                global_temp_file_manager.delete_temp_file(wordlist_result["temp_file_id"])
                temp_cleanup_result = {"success": True, "message": "Temporary file cleaned up successfully"}
            except Exception as e:
                temp_cleanup_result = {"success": False, "error": str(e)}
        else:
            temp_cleanup_result = None
        
        # 步骤5: 分析结果
        analysis = {
            "scan_type": scan_type,
            "wordlist_info": {
                "category": wordlist_category,
                "type": wordlist_type,
                "size": wordlist_result.get("size", "unknown"),
                "lines": wordlist_result.get("lines", "unknown")
            },
            "scan_success": scan_result.get("success", False),
            "findings_count": 0,
            "high_priority_findings": []
        }
        
        # 分析扫描结果
        if scan_result.get("success") and scan_result.get("output"):
            output_lines = scan_result["output"].split("\n")
            analysis["findings_count"] = len(output_lines)
            
            # 提取高优先级发现
            for line in output_lines:
                if any(status in line for status in ["200", "301", "302", "403"]):
                    analysis["high_priority_findings"].append(line)
        
        # 返回综合结果
        return {
            "success": True,
            "workflow": {
                "wordlist_generation": wordlist_result,
                "scan_execution": scan_result,
                "analysis": analysis,
                "temp_file_cleanup": temp_cleanup_result
            },
            "summary": {
                "target": target_url,
                "scan_type": scan_type,
                "wordlist_used": f"{wordlist_category}/{wordlist_type}",
                "transfer_method": "memory" if use_memory else "file_copy",
                "total_findings": analysis["findings_count"],
                "high_priority_findings": len(analysis["high_priority_findings"])
            }
        }

    @mcp.prompt()
    def wordlist_integration_guide() -> str:
        """
        # 工具链集成流程指南

        wordlist_integration_workflow函数提供了一个完整的自动化工作流程，
        集成了SecLists字典生成和扫描工具，实现从字典获取到扫描执行的无缝衔接。

        ## 常用集成场景

        ### 1. 目录发现扫描
        ```python
        wordlist_integration_workflow(
            target_url="http://example.com",
            scan_type="directory",
            wordlist_category="discovery",
            wordlist_type="web-content"
        )
        ```

        ### 2. 子域名枚举
        ```python
        wordlist_integration_workflow(
            target_url="example.com",
            scan_type="subdomain",
            wordlist_category="discovery",
            wordlist_type="dns"
        )
        ```

        ### 3. 虚拟主机发现
        ```python
        wordlist_integration_workflow(
            target_url="http://example.com",
            scan_type="vhost",
            wordlist_category="discovery",
            wordlist_type="vhosts"
        )
        ```

        ### 4. 内存传递方式
        ```python
        wordlist_integration_workflow(
            target_url="http://example.com",
            scan_type="directory",
            wordlist_category="discovery",
            wordlist_type="web-content",
            use_memory=True,
            max_lines=5000
        )
        ```

        ### 5. 自定义扫描选项
        ```python
        scan_options = {
            "extensions": "php,asp,aspx",
            "threads": "50",
            "match_status": "200,301,302,403"
        }
        
        wordlist_integration_workflow(
            target_url="http://example.com",
            scan_type="directory",
            wordlist_category="discovery",
            wordlist_type="web-content",
            scan_options=scan_options
        )
        ```

        ## 核心参数说明

        ### 基本参数
        - target_url (必需): 目标URL或域名
        - scan_type: 扫描类型 ("directory"/"subdomain"/"vhost")
        - wordlist_category: 字典分类 (passwords/usernames/discovery/fuzzing等)
        - wordlist_type: 字典类型 (common/default/rockyou等)

        ### 传递方式参数
        - use_memory: 是否使用内存传递方式 (默认: False)
        - max_lines: 内存传递时的最大行数限制 (默认: 1000)
        - workdir_path: 工作目录路径 (默认: 当前工作目录)

        ### 扫描选项
        - scan_options: 扫描工具的额外选项 (字典格式)

        ## 工作流程说明

        ### 1. 字典生成阶段
        - 根据指定的分类和类型获取SecLists字典
        - 支持内存传递和文件复制两种方式
        - 自动处理路径验证和错误检查

        ### 2. 扫描执行阶段
        - 根据扫描类型选择合适的工具
        - 自动配置扫描参数和字典路径
        - 处理扫描过程中的错误和异常

        ### 3. 结果分析阶段
        - 统计扫描结果和发现数量
        - 提取高优先级发现
        - 生成综合分析报告

        ## 传递方式对比

        ### 内存传递方式
        - 优点: 无文件系统依赖，速度快，适合自动化
        - 缺点: 大字典可能消耗较多内存
        - 适用场景: 自动化脚本，CI/CD流程

        ### 文件复制方式
        - 优点: 内存使用少，适合大型字典
        - 缺点: 需要文件系统操作，可能有路径问题
        - 适用场景: 手动测试，大型字典扫描

        ## 返回结果结构

        ```json
        {
            "success": true,
            "workflow": {
                "wordlist_generation": {...},
                "scan_execution": {...},
                "analysis": {...}
            },
            "summary": {
                "target": "http://example.com",
                "scan_type": "directory",
                "wordlist_used": "discovery/web-content",
                "transfer_method": "memory",
                "total_findings": 25,
                "high_priority_findings": 8
            }
        }
        ```

        ## 注意事项

        1. 确保目标URL有效且可访问
        2. 根据扫描目标选择合适的字典类型
        3. 内存传递方式适合中小型字典，大型字典建议使用文件复制
        4. 扫描结果可能包含大量数据，注意处理和分析
        5. 使用scan_options参数可以自定义扫描工具的行为
        6. 确保有足够的权限执行扫描操作
        """



    @mcp.prompt()
    def temp_file_management_guide() -> str:
        """
        # 临时文件管理指南

        本系统提供了完整的临时文件管理功能，用于跟踪和管理在工具链集成过程中创建的临时文件。
        这些工具可以帮助您更好地管理临时资源，避免磁盘空间浪费和潜在的安全风险。

        ## 核心功能

        ### 1. 创建临时文件
        ```python
        # 创建基本临时文件
        temp_file_create()
        
        # 创建带内容的临时文件
        temp_file_create(content="This is test content")
        
        # 创建自定义后缀的临时文件
        temp_file_create(suffix=".json", content='{"key": "value"}')
        
        # 创建带指定ID的临时文件
        temp_file_create(file_id="my_file", content="Custom ID file")
        ```

        ### 2. 获取文件信息
        ```python
        # 根据ID获取文件路径
        temp_file_get_path(file_id="my_file")
        
        # 列出所有临时文件
        temp_file_list()
        ```

        ### 3. 删除临时文件
        ```python
        # 根据ID删除文件
        temp_file_delete(file_id="my_file")
        
        # 根据路径删除文件
        temp_file_delete(file_path="/tmp/mcp_abc123.txt")
        ```

        ### 4. 批量清理
        ```python
        # 清理超过24小时的文件
        temp_file_cleanup(max_age_hours=24.0)
        
        # 清理超过1小时的文件
        temp_file_cleanup(max_age_hours=1.0)
        
        # 清理所有临时文件
        temp_file_cleanup_all()
        ```

        ### 5. 创建临时目录
        ```python
        # 创建基本临时目录
        temp_file_manager(action="create_dir")
        
        # 创建自定义前缀的临时目录
        temp_file_manager(action="create_dir", prefix="my_project_")
        ```

        ## 最佳实践

        ### 1. 自动化清理
        - 在脚本结束时调用 `temp_file_cleanup_all()` 清理所有临时文件
        - 对于长时间运行的进程，定期调用 `temp_file_cleanup()` 清理旧文件
        - 使用 try-finally 块确保即使发生错误也能清理资源

        ```python
        try:
            # 创建临时文件
            result = temp_file_create(content="Important data")
            file_id = result["file_id"]
            
            # 使用文件进行操作...
            
        finally:
            # 确保清理临时文件
            temp_file_delete(file_id=file_id)
        ```

        ### 2. 文件命名规范
        - 使用有意义的文件ID，便于管理和追踪
        - 使用适当的文件后缀，便于工具识别和处理
        - 使用项目特定的前缀，便于区分不同用途的文件

        ```python
        # 好的示例
        temp_file_create(
            file_id="scan_results_20231201",
            suffix=".json",
            content='{"results": []}'
        )
        
        # 不好的示例
        temp_file_create()  # 难以追踪和管理
        ```

        ### 3. 内存与文件传递对比
        - 小型数据（<1MB）使用内存传递
        - 大型数据（>1MB）使用临时文件
        - 短期使用的数据考虑内存传递
        - 需要多次访问的数据考虑临时文件

        ## 安全注意事项

        1. **敏感数据**: 临时文件可能包含敏感信息，确保及时清理
        2. **权限控制**: 临时文件通常使用系统默认权限，必要时手动设置
        3. **路径泄露**: 避免在日志或输出中泄露临时文件路径
        4. **磁盘空间**: 监控临时文件占用的磁盘空间，定期清理

        ## 集成示例

        ### 与工具链集成
        ```python
        # 在工具链中使用临时文件管理
        def integrated_scan_workflow():
            # 1. 创建临时文件存储字典
            dict_result = temp_file_create(
                file_id="scan_wordlist",
                content="admin\nuser\ntest\npassword"
            )
            
            # 2. 使用临时文件进行扫描
            scan_result = ffuf_scan(
                url="http://example.com",
                wordlist=dict_result["file_path"]
            )
            
            # 3. 创建临时文件存储结果
            results_result = temp_file_create(
                file_id="scan_results",
                suffix=".json",
                content=json.dumps(scan_result)
            )
            
            # 4. 清理临时文件
            temp_file_delete(file_id="scan_wordlist")
            
            return {
                "scan_result": scan_result,
                "results_file": results_result["file_path"]
            }
        ```

        ## 监控和维护

        定期检查临时文件状态：
        ```python
        # 获取临时文件统计信息
        stats = temp_file_list()
        
        # 检查是否有异常多的临时文件
        if stats["stats"]["total_files"] > 100:
            logger.warning(f"High number of temp files: {stats['stats']['total_files']}")
            
        # 检查临时文件总大小
        if stats["stats"]["total_size_mb"] > 500:
            logger.warning(f"Large temp file size: {stats['stats']['total_size_mb']} MB")
        ```

        通过合理使用这些临时文件管理工具，您可以构建更加健壮和安全的安全测试工作流程。
        """

    @mcp.tool()
    def auto_wordlist_management(action: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        自动化的词汇表生成和清理流程
        """
        try:
            # 设置默认配置
            default_config = {
                "max_age_hours": 24.0,
                "wordlist_types": ["common", "admin", "api"],
                "cleanup_after_generate": True
            }
            
            # 合并用户配置
            if config:
                final_config = {**default_config, **config}
            else:
                final_config = default_config
            
            result = {
                "success": True,
                "action": action,
                "config": final_config,
                "timestamp": datetime.datetime.now().isoformat(),
                "operations": []
            }
            
            # 根据操作类型执行相应功能
            if action in ["cleanup", "full"]:
                # 清理过期临时文件
                cleanup_result = temp_file_cleanup(max_age_hours=final_config["max_age_hours"])
                result["operations"].append({
                    "operation": "cleanup",
                    "status": "success" if cleanup_result["success"] else "failed",
                    "details": cleanup_result
                })
            
            if action in ["generate", "full"]:
                # 生成预定义字典
                for wordlist_type in final_config["wordlist_types"]:
                    try:
                        if wordlist_type == "common":
                            # 生成常用密码字典
                            common_passwords = [
                                "admin", "password", "123456", "root", "test",
                                "guest", "user", "login", "welcome", "qwerty"
                            ]
                            wordlist_content = "\n".join(common_passwords)
                            
                            wordlist_result = temp_file_create(
                                file_id=f"auto_common_{int(time.time())}",
                                content=wordlist_content,
                                suffix=".txt"
                            )
                            
                            result["operations"].append({
                                "operation": "generate_common",
                                "status": "success",
                                "file_id": wordlist_result["file_id"],
                                "file_path": wordlist_result["file_path"],
                                "size": wordlist_result["size"]
                            })
                        
                        elif wordlist_type == "admin":
                            # 生成管理员账户字典
                            admin_accounts = [
                                "admin", "administrator", "root", "superuser",
                                "sa", "manager", "supervisor", "operator"
                            ]
                            wordlist_content = "\n".join(admin_accounts)
                            
                            wordlist_result = temp_file_create(
                                file_id=f"auto_admin_{int(time.time())}",
                                content=wordlist_content,
                                suffix=".txt"
                            )
                            
                            result["operations"].append({
                                "operation": "generate_admin",
                                "status": "success",
                                "file_id": wordlist_result["file_id"],
                                "file_path": wordlist_result["file_path"],
                                "size": wordlist_result["size"]
                            })
                        
                        elif wordlist_type == "api":
                            # 生成API端点字典
                            api_endpoints = [
                                "/api", "/api/v1", "/api/v2", "/rest", "/rest/api",
                                "/graphql", "/swagger", "/docs", "/admin", "/login"
                            ]
                            wordlist_content = "\n".join(api_endpoints)
                            
                            wordlist_result = temp_file_create(
                                file_id=f"auto_api_{int(time.time())}",
                                content=wordlist_content,
                                suffix=".txt"
                            )
                            
                            result["operations"].append({
                                "operation": "generate_api",
                                "status": "success",
                                "file_id": wordlist_result["file_id"],
                                "file_path": wordlist_result["file_path"],
                                "size": wordlist_result["size"]
                            })
                    
                    except Exception as e:
                        result["operations"].append({
                            "operation": f"generate_{wordlist_type}",
                            "status": "failed",
                            "error": str(e)
                        })
            
            # 如果配置了生成后清理，则执行清理
            if action == "generate" and final_config["cleanup_after_generate"]:
                cleanup_result = temp_file_cleanup(max_age_hours=final_config["max_age_hours"])
                result["operations"].append({
                    "operation": "post_generate_cleanup",
                    "status": "success" if cleanup_result["success"] else "failed",
                    "details": cleanup_result
                })
            
            # 统计操作结果
            success_count = sum(1 for op in result["operations"] if op["status"] == "success")
            result["summary"] = {
                "total_operations": len(result["operations"]),
                "successful_operations": success_count,
                "failed_operations": len(result["operations"]) - success_count
            }
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Auto wordlist management failed: {str(e)}",
                "action": action,
                "config": config
            }

    @mcp.prompt()
    def auto_wordlist_management_guide() -> str:
        """
        # 自动化词汇表管理指南

        本系统提供了自动化的词汇表生成和清理功能，帮助您更高效地管理安全测试中使用的字典文件。

        ## 核心功能

        ### 1. 自动清理过期文件
        ```python
        # 清理超过24小时的临时文件
        auto_wordlist_management(action="cleanup", config={
            "max_age_hours": 24.0
        })
        
        # 清理超过1小时的临时文件
        auto_wordlist_management(action="cleanup", config={
            "max_age_hours": 1.0
        })
        ```

        ### 2. 自动生成预定义字典
        ```python
        # 生成所有类型的预定义字典
        auto_wordlist_management(action="generate", config={
            "wordlist_types": ["common", "admin", "api"]
        })
        
        # 只生成常用密码字典
        auto_wordlist_management(action="generate", config={
            "wordlist_types": ["common"]
        })
        ```

        ### 3. 完整自动化流程
        ```python
        # 执行完整的自动化流程（清理+生成）
        auto_wordlist_management(action="full", config={
            "max_age_hours": 12.0,
            "wordlist_types": ["common", "admin", "api"],
            "cleanup_after_generate": True
        })
        ```

        ## 配置参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| max_age_hours | float | 24.0 | 文件最大保留时间(小时) |
| wordlist_types | list | ["common", "admin", "api"] | 要生成的字典类型列表 |
| cleanup_after_generate | bool | True | 生成后是否清理旧文件 |

## 字典类型说明

### 1. common - 常用密码字典
包含最常见的密码和凭证：
- admin, password, 123456, root, test
- guest, user, login, welcome, qwerty

### 2. admin - 管理员账户字典
包含常见的管理员用户名：
- admin, administrator, root, superuser
- sa, manager, supervisor, operator

### 3. api - API端点字典
包含常见的API路径：
- /api, /api/v1, /api/v2, /rest, /rest/api
- /graphql, /swagger, /docs, /admin, /login

## 使用场景示例

### 1. 定期维护任务
```python
# 每日维护任务
def daily_maintenance():
    # 清理超过24小时的临时文件
    result = auto_wordlist_management(action="cleanup", config={
        "max_age_hours": 24.0
    })
    
    print(f"清理完成: {result['summary']['successful_operations']} 个操作成功")
    
    # 生成新的字典文件
    result = auto_wordlist_management(action="generate", config={
        "wordlist_types": ["common", "admin"]
    })
    
    print(f"字典生成完成: {result['summary']['successful_operations']} 个字典已生成")
```

### 2. 测试前准备
```python
# 安全测试前准备
def prepare_for_security_test():
    # 执行完整自动化流程
    result = auto_wordlist_management(action="full", config={
        "max_age_hours": 6.0,  # 清理6小时前的文件
        "wordlist_types": ["common", "admin", "api"],
        "cleanup_after_generate": True
    })
    
    # 提取生成的字典文件路径
    wordlist_files = {}
    for op in result["operations"]:
        if op["status"] == "success" and "file_path" in op:
            wordlist_type = op["operation"].replace("generate_", "")
            wordlist_files[wordlist_type] = op["file_path"]
    
    return wordlist_files
```

### 3. 集成到CI/CD流程
```python
# CI/CD集成示例
def ci_cd_integration():
    # 清理所有临时文件
    cleanup_result = auto_wordlist_management(action="cleanup", config={
        "max_age_hours": 0.1  # 清理所有文件
    })
    
    if not cleanup_result["success"]:
        print(f"清理失败: {cleanup_result.get('error', 'Unknown error')}")
        return False
    
    # 生成测试所需的字典
    generate_result = auto_wordlist_management(action="generate", config={
        "wordlist_types": ["common", "api"]
    })
    
    if not generate_result["success"]:
        print(f"生成失败: {generate_result.get('error', 'Unknown error')}")
        return False
    
    return True
```

## 最佳实践

1. **定期清理**: 根据项目需求设置合适的清理频率，避免临时文件占用过多磁盘空间
2. **按需生成**: 只生成测试所需的字典类型，减少不必要的资源消耗
3. **监控使用**: 定期检查临时文件的使用情况，优化清理策略
4. **自动化集成**: 将自动化词汇表管理集成到您的工作流程中，提高效率

通过使用这些自动化工具，您可以更专注于安全测试本身，而无需手动管理字典文件和临时资源。
        """

    # 系统工具 - 健康检查与通用命令
    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        [系统工具] 检查PST API服务器健康状态。
        """
        return pst_client.check_health()

    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        return pst_client.execute_command(command)

    @mcp.tool()
    def pw_list_tools(branch: str = "main") -> Dict[str, Any]:
        """
        [系统工具] 列出PST工具库中的所有可用工具包括工具描述和分类信息
        """
        return pst_client.safe_get("api/catalog/pentest_windows", {"branch": branch})

    @mcp.tool()
    def pst_installed_tools() -> Dict[str, Any]:
        """
        [系统工具] 列出已安装的PST工具，包括工具版本和状态信息，用于检查系统环境配置和工具可用性
        """
        return pst_client.safe_get("api/catalog/installed")

    # 系统工具 - 临时文件管理
    @mcp.tool()
    def manage_temp_files(
        action: str,
        file_id: str = "",
        file_path: str = "",
        content: str = "",
        suffix: str = ".txt",
        prefix: str = "mcp_",
        max_age_hours: float = 24.0
    ) -> Dict[str, Any]:
        """
        [系统工具] 临时文件和目录管理工具，提供临时文件和目录的创建、查询、删除、列表和清理功能
        """
        try:
            if action == "create":
                # 创建临时文件
                if file_id:
                    file_path = global_temp_file_manager.create_temp_file_with_id(
                        file_id=file_id,
                        content=content,
                        suffix=suffix,
                        prefix=prefix
                    )
                    return {
                        "success": True,
                        "file_id": file_id,
                        "file_path": file_path,
                        "message": f"创建临时文件成功，ID: {file_id}"
                    }
                else:
                    file_path = global_temp_file_manager.create_temp_file(
                        content=content,
                        suffix=suffix,
                        prefix=prefix
                    )
                    
                    # 获取生成的文件ID
                    for fid, finfo in global_temp_file_manager.temp_files.items():
                        if finfo["path"] == file_path:
                            return {
                                "success": True,
                                "file_id": fid,
                                "file_path": file_path,
                                "message": f"创建临时文件成功，自动生成ID: {fid}"
                            }
                    
                    return {
                        "success": False,
                        "error": "无法获取文件ID"
                    }
            
            elif action == "create_dir":
                # 创建临时目录
                dir_path = global_temp_file_manager.create_temp_dir(prefix)
                return {
                    "success": True,
                    "dir_path": dir_path,
                    "message": f"创建临时目录成功: {dir_path}"
                }
            
            elif action == "get_path":
                # 获取文件路径
                if not file_id:
                    return {
                        "success": False,
                        "error": "获取文件路径需要提供file_id参数"
                    }
                
                file_path = global_temp_file_manager.get_temp_file_path(file_id)
                if file_path:
                    return {
                        "success": True,
                        "file_id": file_id,
                        "file_path": file_path,
                        "exists": os.path.exists(file_path)
                    }
                else:
                    return {
                        "success": False,
                        "error": f"未找到ID为 {file_id} 的文件"
                    }
            
            elif action == "delete":
                # 删除文件
                if file_id:
                    success = global_temp_file_manager.delete_temp_file(file_id)
                    if success:
                        return {
                            "success": True,
                            "message": f"删除临时文件成功，ID: {file_id}"
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"删除临时文件失败，ID: {file_id} 或文件不存在"
                        }
                elif file_path:
                    success = global_temp_file_manager.delete_temp_file_by_path(file_path)
                    if success:
                        return {
                            "success": True,
                            "message": f"删除临时文件成功，路径: {file_path}"
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"删除临时文件失败，路径: {file_path} 或文件不存在"
                        }
                else:
                    return {
                        "success": False,
                        "error": "删除文件需要提供file_id或file_path参数"
                    }
            
            elif action == "list":
                # 列出所有文件
                temp_files = global_temp_file_manager.list_temp_files()
                stats = global_temp_file_manager.get_temp_file_stats()
                
                return {
                    "success": True,
                    "files": temp_files,
                    "stats": stats,
                    "count": len(temp_files)
                }
            
            elif action == "cleanup":
                # 清理旧文件
                deleted_count = global_temp_file_manager.cleanup_temp_files(max_age_hours)
                return {
                    "success": True,
                    "deleted_count": deleted_count,
                    "max_age_hours": max_age_hours,
                    "message": f"清理了 {deleted_count} 个超过 {max_age_hours} 小时的临时项目"
                }
            
            elif action == "cleanup_all":
                # 清理所有文件
                deleted_count = global_temp_file_manager.cleanup_all_temp_files()
                return {
                    "success": True,
                    "deleted_count": deleted_count,
                    "message": f"清理了所有 {deleted_count} 个临时项目"
                }
            
            else:
                return {
                    "success": False,
                    "error": f"不支持的操作类型: {action}。支持的操作: create, create_dir, get_path, delete, list, cleanup, cleanup_all"
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"临时文件管理操作失败: {str(e)}"
            }

    return mcp


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="运行Windows PST MCP客户端")
    parser.add_argument("--server", type=str, default=DEFAULT_PST_SERVER, help=f"PST API服务器URL (默认: {DEFAULT_PST_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT, help=f"请求超时时间(秒) (默认: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="启用调试日志")
    parser.add_argument("--log-file", type=str, help="日志文件路径")
    
    # 新增参数
    parser.add_argument("--host", type=str, default="127.0.0.1", help="MCP服务器主机 (默认: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="MCP服务器端口 (默认: 8000)")
    parser.add_argument("--path", type=str, default="/mcp", help="MCP服务器访问路径 (默认: /mcp)")
    parser.add_argument("--transport", type=str, default="studio", choices=["studio", "sse", "http"], help="MCP服务器启动模式 (默认: studio)")
    
    return parser.parse_args()


@monitor_performance
def main():
    """主函数"""
    try:
        # 解析命令行参数
        args = parse_args()
        
        # 设置日志
        logger = setup_logging(args.debug, args.log_file)
        logger.info("启动PST MCP服务器")
        
        # 初始化PST客户端
        logger.info(f"初始化PST工具客户端，服务器地址: {args.server}")
        pst_client = PSTToolsClient(args.server, args.timeout)
        
        # 检查服务器健康状态
        logger.info("检查PST API服务器健康状态")
        health = pst_client.check_health()
        
        if "error" in health:
            logger.warning(f"无法连接到PST API服务器 {args.server}: {health['error']}")
            logger.warning("MCP服务器将启动，但工具执行可能会失败")
        else:
            logger.info(f"成功连接到PST API服务器 {args.server}")
            logger.info(f"服务器健康状态: {health.get('status')}")
            
            if not health.get("all_essential_tools_available", False):
                missing = [t for t, ok in health.get("tools_status", {}).items() if not ok]
                if missing:
                    logger.warning(f"缺少工具: {', '.join(missing)}")
        
        # 设置MCP服务器
        logger.info("设置MCP服务器")
        mcp = setup_mcp_server(pst_client)
        logger.info(f"以{args.transport}模式启动PST MCP服务器")
        
        # 启动服务器
        transport_map = {
            "studio": "stdio",
            "sse": "sse",
            "http": "streamable-http"
        }
        transport_mode = transport_map.get(args.transport)
        
        if not transport_mode:
            logger.error(f"无效的启动模式: {args.transport}")
            return 1
        
        try:
            if transport_mode == 'sse':
                logger.info(f"启动SSE服务器，监听 {args.host}:{args.port}")
                app = mcp.sse_app()
                uvicorn.run(app, host=args.host, port=args.port)
            elif transport_mode == 'streamable-http':
                logger.info(f"启动HTTP服务器，监听 {args.host}:{args.port}")
                app = mcp.streamable_http_app()
                uvicorn.run(app, host=args.host, port=args.port)
            else:
                logger.info("启动stdio模式服务器")
                mcp.run(transport=transport_mode)
        except KeyboardInterrupt:
            logger.info("收到中断信号，正在关闭服务器")
            return 0
        except Exception as e:
            logger.error(f"服务器启动失败: {str(e)}")
            logger.debug(f"服务器启动异常详情:\n{traceback.format_exc()}")
            return 1
        finally:
            # 清理资源
            try:
                pst_client.close()
                global_temp_file_manager.cleanup_all_temp_files()
                logger.info("资源清理完成")
            except Exception as e:
                logger.error(f"资源清理失败: {str(e)}")
        
        return 0
    except Exception as e:
        logger.error(f"主函数执行失败: {str(e)}")
        logger.debug(f"主函数异常详情:\n{traceback.format_exc()}")
        return 1


if __name__ == "__main__":
    sys.exit(main())