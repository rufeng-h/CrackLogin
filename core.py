"""
 author rufeng
 date 2021/11/12/11:47
 description 
"""
import logging
import os
import subprocess
import typing
from abc import ABCMeta, abstractmethod
from pathlib import Path

import requests
from requests import Session

import log
from manager import SessionManager, DefaultSessionManager

PROJECT_DIR = Path(__file__).parent.absolute()

headers = {
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'sec-ch-ua': '"Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'Sec-Fetch-Dest': 'script',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'cross-site',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/95.0.4638.69 Safari/537.36',
}


class Login(metaclass=ABCMeta):
    def __init__(self, session_manager: SessionManager = None, log_level=logging.INFO, **kwargs):
        # DEBUG模式
        if log_level < logging.INFO:
            self.session_manager = None
        else:
            self.session_manager = session_manager or DefaultSessionManager()

        self.session = (self.session_manager and self.session_manager.load_session(**kwargs)) or requests.Session()

        self._logger = log.get_logger(self.__class__.__name__, log_level)

    @abstractmethod
    def _do_login(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def is_login(self) -> bool:
        raise NotImplementedError

    @typing.final
    def login(self) -> Session:
        if self.is_login():
            self._logger.info("cookie有效!")
            return self.session
        self._logger.info("不存在cookie或cookie过时!，重新登录!")

        try:
            self._do_login()
        except Exception as e:
            self._logger.error(e, exc_info=True)
            exit(0)

        self._logger.info("登录成功")

        if self.session_manager:
            self.session_manager.store_session(self.session)

        return self.session

    @abstractmethod
    def _initialize_http(self) -> None:
        raise NotImplementedError


class NodeEncryptor():
    def __init__(self, username, password, js_file_path, node_exec_path=None, node_server_port=8000):
        if not hasattr(self, "_logger"):
            self._logger = log.get_logger(self.__class__.__name__)
        if not js_file_path.exists():
            self._logger.error("js文件不存在!")
            exit(0)
        self._node_server = NodeServer(str(js_file_path), node_exec_path, node_server_port)
        self._username, self._password = username, password


class NodeServer(object):
    def __init__(self, js_path: str, node_exec_path=None, node_server_port: int = 8000):
        self._js_path = js_path
        self._node_server_port = node_server_port
        self._node_exec_path = node_exec_path or "node"
        self._proc = None
        self._logger = log.get_logger(self.__class__.__name__)
        self.url = f"http://localhost:{node_server_port}"

    def run(self):
        if self._proc:
            return

        self._check_node_env()

        os.environ.setdefault("crackLoginNodeServerPort", str(self._node_server_port))
        self._proc = subprocess.Popen([self._node_exec_path, self._js_path])
        if self._proc.poll() is None:
            self._logger.info(f"node server is running at http://localhost:{self._node_server_port}")

    def stop(self):
        if not self._proc:
            return

        if self._proc.poll() is None:
            self._proc.kill()
            self._logger.info("stop node server")

        os.environ.pop("crackLoginNodeServerPort")

    def _check_node_env(self):
        try:
            p = subprocess.run([self._node_exec_path, "-v"], stdout=subprocess.PIPE)
            self._logger.info(f"系统node版本：{p.stdout.decode()}")
        except FileNotFoundError:
            self._logger.error("未检测到node环境")
            exit(0)
