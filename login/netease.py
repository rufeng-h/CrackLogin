"""
 author rufeng
 date 2021/11/14/9:36
 description 
"""
import base64
import binascii
import logging
import time
from abc import ABCMeta

import qrcode
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from core import headers, Login
from exceptions import LoginFailedException
from manager import SessionManager
from utils import random_ascii


class NeteaseLogin(Login, metaclass=ABCMeta):
    def __init__(self, session_manager: SessionManager = None, log_level: int = logging.INFO):
        super().__init__(session_manager, log_level)
        self._initialize_http()

    def _initialize_http(self) -> None:
        self.session.headers.update(headers)
        self._test_login_url = "https://music.163.com/user/update"

    def is_login(self) -> bool:
        return self.session.get(self._test_login_url, allow_redirects=False).status_code == 200


class NeteaseEncryptor(object):
    _aes_iv = b"0102030405060708"
    _aes_key = b'0CoJUm6Qyw8W8jud'
    _rsa_pubkey = "010001"
    _rsa_modules = "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7"
    _aes_block_size = 16

    @staticmethod
    def _random_str() -> str:
        return random_ascii()

    @staticmethod
    def _aes_encrypt(msg: str, key: bytes) -> str:
        padded = pad(msg.encode(), NeteaseEncryptor._aes_block_size)
        return base64.b64encode(
            AES.new(key=key, mode=AES.MODE_CBC, IV=NeteaseEncryptor._aes_iv).encrypt(padded)).decode()

    @staticmethod
    def _rsa_encrypt(msg: str):
        v = pow(int(msg, 16), int(NeteaseEncryptor._rsa_pubkey, 16), int(NeteaseEncryptor._rsa_modules, 16))
        return format(v, 'x').zfill(256)

    @staticmethod
    def encrypt(msg: str) -> dict:
        random_str = NeteaseEncryptor._random_str()
        enc_text = NeteaseEncryptor._aes_encrypt(msg, NeteaseEncryptor._aes_key)
        enc_text = NeteaseEncryptor._aes_encrypt(enc_text, random_str.encode())
        hex_str = binascii.hexlify(random_str[::-1].encode()).decode()
        return {"params": enc_text,
                "encSecKey": NeteaseEncryptor._rsa_encrypt(hex_str)}


class NeteaseLoginScanQr(NeteaseLogin):
    def _initialize_http(self) -> None:
        super()._initialize_http()
        self._unique_key_url = "https://music.163.com/weapi/login/qrcode/unikey?csrf_token="
        self._check_scan_url = "https://music.163.com/weapi/login/qrcode/client/login?csrf_token="
        self._csrf_token = ""

    def _wait_for_scan(self, key: str):
        img = qrcode.make(data="http://music.163.com/login?codekey={}".format(key))
        img.show()
        msg = f'{{\"key\":\"{key}\",\"type\":\"1\",\"csrf_token\":\"{self._csrf_token}\"}}'
        authorized = False
        while not authorized:
            ret = self.session.post(self._check_scan_url, data=NeteaseEncryptor.encrypt(msg)).json()

            if ret['code'] == 802:
                self._logger.info(ret['nickname'])

            if ret['code'] == 803:
                authorized = True

            self._logger.info(ret['message'])

            time.sleep(1.5)

    def _get_user_info(self):
        res = self.session.post("https://music.163.com/weapi/w/nuser/account/get",
                                params={"csrf_token": self._csrf_token},
                                data=NeteaseEncryptor.encrypt(f'{{\"csrf_token\":\"{self._csrf_token}\"}}'))
        profile = res.json()['profile']
        uid, nickname = profile["userId"], profile["nickname"]
        last_login_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(profile["lastLoginTime"] / 1000))
        self._logger.info(
            f'uid: {uid}, nickname: {nickname}, 上次登录：{last_login_time}')

    def _do_login(self) -> None:
        ret = self.session.post(self._unique_key_url,
                                data=NeteaseEncryptor.encrypt(
                                    f'{{\"type\":\"1\",\"csrf_token\":\"{self._csrf_token}\"}}')).json()
        self._wait_for_scan(ret['unikey'])
        self._csrf_token = self.session.cookies.get("__csrf")
        self._get_user_info()
        if not self.is_login():
            raise LoginFailedException


if __name__ == '__main__':
    res = requests.post("https://music.163.com/weapi/search/suggest/web?csrf_token=",
                        data=NeteaseEncryptor.encrypt('{\"s\":\"王菲\",\"limit\":\"8\",\"csrf_token\":\"\"}'),
                        headers=headers)
    print(res.text)
    NeteaseLoginScanQr().login()
