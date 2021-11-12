"""
 author rufeng
 date 2021/11/12/11:47
 description 
"""
from abc import ABCMeta, abstractmethod

import requests
from requests import Session

from session.manager import SessionManager, DefaultSessionManager


class Login(metaclass=ABCMeta):
    def __init__(self, session_manager: SessionManager = None, **kwargs):
        self.session_manager = session_manager or DefaultSessionManager()
        self.session = self.session_manager.load_session(**kwargs) or requests.Session()

    @abstractmethod
    def login(self) -> Session:
        raise NotImplementedError

    @abstractmethod
    def is_login(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def _initialize_http(self):
        raise NotImplementedError
