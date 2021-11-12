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

import requests
from requests import Session

import log
from manager import SessionManager, DefaultSessionManager


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
    def _do_login(self) -> bool:
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

        if not self._do_login():
            raise SystemExit("登录失败")

        if self.session_manager:
            self.session_manager.store_session(self.session)

    @abstractmethod
    def _initialize_http(self) -> None:
        raise NotImplementedError


class NodeServer(object):
    def __init__(self, js_path: str, node_exec_path=None, node_server_port: int = 8000):
        self._js_path = js_path
        self._node_server_port = node_server_port
        self._node_exec_path = node_exec_path or "node"
        self._proc = None
        self._logger = log.get_logger(self.__class__.__name__)

        try:
            subprocess.run([self._node_exec_path, "-v"], stdout=subprocess.PIPE)
        except FileNotFoundError:
            raise SystemExit("未检测到node环境")

    def run(self):
        if self._proc:
            return

        os.environ.setdefault("crackLoginNodeServerPort", str(self._node_server_port))
        self._proc = subprocess.Popen([self._node_exec_path, self._js_path])
        self._logger.info(f"node server is running at http://localhost:{self._node_server_port}")

    def stop(self):
        if not self._proc:
            return

        self._proc.kill()
        os.environ.pop("crackLoginNodeServerPort")
        self._logger.info("stop node server")
