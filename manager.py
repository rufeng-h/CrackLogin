"""
 author rufeng
 date 2021/11/12/11:08
 description 
"""
import io
import pickle
import typing
from abc import abstractmethod, ABCMeta

from redis import StrictRedis
from requests import Session


class SessionManager(metaclass=ABCMeta):
    @abstractmethod
    def store_session(self, session: Session):
        raise NotImplementedError

    @abstractmethod
    def load_session(self, **kwargs):
        raise NotImplementedError


class RedisSessionManager(SessionManager):
    def __init__(self, username):
        self._redis = StrictRedis()
        self._redis_key = f"weibo:login:{username}"

    def store_session(self, session: Session):
        oo = io.BytesIO()
        pickle.dump(session, oo)
        self._redis.set(self._redis_key, oo.getvalue())

    def load_session(self, **kwargs) -> typing.Union[Session, None]:
        value = self._redis.get(self._redis_key)
        if not value:
            return None
        return pickle.loads(value)


class DefaultSessionManager(SessionManager):

    def store_session(self, session: Session):
        with open("./session.pkl", "wb") as f:
            pickle.dump(session, f)

    def load_session(self, **kwargs):
        try:
            with open("./session.pkl", "rb") as f:
                return pickle.load(f)
        except FileNotFoundError:
            return None
