"""
 author rufeng
 date 2021/11/12/22:10
 description 
"""
import logging
import os
from pathlib import Path

from core import Login, NodeEncryptor, headers, PROJECT_DIR
from exceptions import LoginFailedException
from manager import SessionManager


class MiGuLogin(Login):

    def __init__(self, session_manager: SessionManager = None, log_level=logging.INFO, **kwargs):
        super().__init__(session_manager, log_level, **kwargs)
        self._initialize_http()

    def _initialize_http(self) -> None:
        self.session.headers.update(headers)
        self._portal_url = "https://passport.migu.cn/portal"
        self._open_login_url = "https://passport.migu.cn/login?sourceid=100001&apptype=0&forceAuthn=false&isPassive=false&authType=MiguPassport&passwordControl=0&display=web&referer=https://passport.migu.cn/portal&logintype=1&qq=null&weibo=null&alipay=null&weixin=null&andPass=null&phoneNumber=&callbackURL=&relayState=&openPage=&hideRegister=&hideForgetPass=&sim=&needOneKey=0&hideps=0"
        self._test_login_url = "https://passport.migu.cn/portal/home/profile"

    def is_login(self) -> bool:
        response = self.session.get(self._test_login_url, allow_redirects=False)
        return response.status_code == 200


class MiGuLoginByPassword(MiGuLogin, NodeEncryptor):
    _js_file_path = PROJECT_DIR.joinpath(Path(os.sep.join(("js", "migu", "server.js"))))

    def __init__(self, username, password, **kwargs):
        super().__init__(**kwargs)
        NodeEncryptor.__init__(self, username, password, self._js_file_path)

    def _initialize_http(self) -> None:
        super()._initialize_http()
        self._auth_url = "https://passport.migu.cn/authn"

    def _do_login_internal(self):
        self.session.get(self._open_login_url)
        self.session.post("https://passport.migu.cn/password/publickey")
        formdata = self.session.post(self._node_server.url,
                                     data={"username": self._username, "password": self._password}).json()
        formdata.update({"isAsync": "true", "sourceID": "100001",
                         "appType": 0,
                         "relayState": "", "captcha": "",
                         "imgcodeType": 1})
        ret = self.session.post(self._auth_url, data=formdata).json()["result"]
        redirect_url, token = ret["redirectURL"], ret["token"]
        params = {"callbackURL": "",
                  "relayState": "",
                  "token": token}
        self.session.get(redirect_url, params=params)
        if not self.is_login():
            raise LoginFailedException

    def _do_login(self) -> None:
        self._node_server.run()
        try:
            self._do_login_internal()
        finally:
            self._node_server.stop()


if __name__ == '__main__':
    MiGuLoginByPassword("18280484271", "Aa1029384756").login()
