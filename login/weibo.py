"""
 author rufeng
 date 2021/11/12/11:37
 description 
"""
import base64
import hashlib
import logging
import os
import re
import time
from abc import ABCMeta
from pathlib import Path

from scrapy import Selector

import utils
from core import Login, NodeEncryptor, headers, PROJECT_DIR
from exceptions import LoginFailedException
from manager import SessionManager


class WeiboLogin(Login, metaclass=ABCMeta):
    def __init__(self, session_manager: SessionManager = None, log_level=logging.INFO, **kwargs):
        """
        :param session_manager: SessionManager
        :param kwargs: kwargs for session_manager load_sesson method
        """
        super().__init__(session_manager=session_manager, log_level=log_level, **kwargs)
        self._initialize_http()
        self._gen_visitor()

    def _gen_visitor(self):
        gen_visotor_url = "https://passport.weibo.com/visitor/genvisitor"
        data = {'cb': 'gen_callback',
                'fp': '{"os":"1","browser":"Chrome95,0,4638,69","fonts":"undefined","screenInfo":"1536*864*24",'
                      '"plugins":"Portable Document Format::internal-pdf-viewer::PDF Viewer|Portable Document '
                      'Format::internal-pdf-viewer::Chrome PDF Viewer|Portable Document '
                      'Format::internal-pdf-viewer::Chromium PDF Viewer|Portable Document '
                      'Format::internal-pdf-viewer::Microsoft Edge PDF Viewer|Portable Document '
                      'Format::internal-pdf-viewer::WebKit built-in PDF"}'}
        response = self.session.post(gen_visotor_url, data=data)
        tid = re.search('"tid":"(.*?)"', response.text).group(1)
        tid = re.sub(r"\\/", "/", tid)
        self.session.cookies.set("tid", tid + "__095", domain='.passport.weibo.com', path='/visitor')
        params = {"a": "incarnate",
                  "t": tid,
                  "w": "2",
                  "c": "095",
                  "gc": "",
                  "cb": "cross_domain",
                  "from": "weibo",
                  "_rand": "0.5799231670299148"}
        self.session.get("https://passport.weibo.com/visitor/visitor", params=params, allow_redirects=False)

        self._logger.debug("sina visitor cookies:")
        for k in self.session.cookies:
            self._logger.debug(f"{k.name} = {k.value}, {k.domain}")

    def _cross_domain(self):
        """
        ??????cookie???.login.sina.com???weibo.com
        :return:
        """
        sub = self.session.cookies.get("SUB", domain=".sina.com.cn")
        subp = self.session.cookies.get("SUBP", domain=".sina.com.cn")
        self.session.cookies.clear(domain=".sina.com.cn", name="SUB", path="/")
        self.session.cookies.clear(domain=".sina.com.cn", name="SUBP", path="/")
        self.session.cookies.set("SUB", sub, domain=".weibo.com")
        self.session.cookies.set("SUBP", subp, domain=".weibo.com")

    def _initialize_http(self):
        self.session.headers.update(headers)
        self._test_login_url = "https://security.weibo.com/account/security"


class WeiboLoginVerifyCode(WeiboLogin, NodeEncryptor):
    _js_file_path = PROJECT_DIR.joinpath(Path(os.sep.join(("js", "weibo", "weibo_pc.js"))))

    def __init__(self, username, password, node_exec_path: str = None, node_server_port: int = 8000,
                 session_manager: SessionManager = None,
                 log_level=logging.INFO, **kwargs):
        super(WeiboLoginVerifyCode, self).__init__(log_level=log_level, session_manager=session_manager, **kwargs)

        NodeEncryptor.__init__(self, username, password, self._js_file_path, node_exec_path=node_exec_path,
                               node_server_port=node_server_port)

    def _pre_login(self):
        pre_login_time_start = int(time.time() * 1000)

        self.session.headers["Referer"] = "https://weibo.com/"

        response = self.session.get(
            self._prelogin_url.format(base64.b64encode(self._username.encode()), int(time.time() * 1000)))

        data = utils.jsoncallback_str2json(response.text)

        self.session.headers.pop("Referer")
        return pre_login_time_start, data

    def _post_form(self, pre_login_time_start: int, data: dict) -> str:
        """
        ?????????????????????????????????url
        :param pre_login_time_start:
        :param data:
        :return:
        """
        enc_pwd = self.session.post(self._node_server.url,
                                    data={"password": self._password, "servertime": data["servertime"],
                                          "nonce": data["nonce"],
                                          "pubkey": data["pubkey"]}).text
        self._login_form["su"] = base64.b64encode(self._username.encode())
        self._login_form["sp"] = enc_pwd
        self._login_form["prelt"] = int(time.time()) - pre_login_time_start - data["exectime"]
        self._login_form["servertime"] = data["servertime"]
        self._login_form["rsakv"] = data["rsakv"]
        self._login_form["nonce"] = data["nonce"]
        response = self.session.post(self._login_url, data=self._login_form)
        return re.search('location\.replace\("(.*?)"\)', response.content.decode("gbk")).group(1)

    def _get_sms_code(self, protection_url, token) -> str:
        """
        ??????????????????????????????encrypt_mobile
        :param protection_url:
        :param token:
        :return:
        """
        res = self.session.get(protection_url)
        selector = Selector(text=res.content.decode())
        encrypt_mobile = selector.xpath('//input[@name="encrypt_mobile"]/@value').extract_first()

        res = self.session.post(self._send_code_url.format(token),
                                data={"encrypt_mobile": encrypt_mobile})
        ret = res.json()

        if ret['retcode'] != 20000000:
            self._logger.error(ret["msg"])
            raise LoginFailedException
        self._logger.info("???????????????????????????")
        return encrypt_mobile

    def _do_redirect(self, redirect_url) -> tuple:
        """
        ???????????????url?????????token???????????????????????????url
        :param redirect_url:
        :return:
        """
        res = self.session.get(redirect_url)

        # TODO
        token = re.search('token=(.*?)"', res.text).group(1)
        protection_url = utils.jsoncallback_str2json(res.text)["protection_url"]

        return token, protection_url

    def _do_login(self) -> None:
        self._node_server.run()

        try:
            self.session.get(self._login_url)
            pre_login_time_start, data = self._pre_login()
            redirect_url = self._post_form(pre_login_time_start, data)
            token, protection_url = self._do_redirect(redirect_url)
            encrypt_mobile = self._get_sms_code(protection_url, token)
            redirect_url = self._verify_code(encrypt_mobile, token)

            self._cross_domain()
            self.session.cookies.pop("cross_origin_proto")
            self.session.cookies.pop("login_sid_t")
            # TODO
        finally:
            self._node_server.stop()

    def is_login(self) -> bool:
        pass

    def _initialize_http(self) -> None:
        super(WeiboLoginVerifyCode, self)._initialize_http()
        self._login_url = "https://weibo.com/login.php"
        self._prelogin_url = "https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su={}&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.19)&_{}"
        self._login_form = {"entry": "weibo",
                            "gateway": "1",
                            "from": "",
                            "savestate": "7",
                            "qrcode_flag": "false",
                            "useticket": "1",
                            "pagerefer": "https://weibo.com/newlogin?tabtype=weibo&gid=102803&url=https%3A%2F%2Fwww.weibo.com%2F",
                            "vsnf": "1",
                            "su": "",
                            "service": "miniblog",
                            "servertime": "",
                            "nonce": "",
                            "pwencode": "rsa2",
                            "rsakv": "",
                            "sp": "",
                            "sr": "1536*864",
                            "encoding": "UTF-8",
                            "prelt": "",
                            "url": "https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
                            "returntype": "META"}
        self._send_code_url = "https://passport.weibo.com/protection/mobile/sendcode?token={}"
        self._confirm_code_url = "https://passport.weibo.com/protection/mobile/confirm?token={}"

    def _verify_code(self, encrypt_mobile, token) -> str:
        while True:
            code = input("????????????????????????????????????")

            ret = self.session.post(self._confirm_code_url.format(token),
                                    data={"encrypt_mobile": encrypt_mobile,
                                          "code": code}).json()
            if ret['code'] != 20000000:
                self._logger.warning(ret['msg'])
                continue

            return ret['data']["redirect_url"]


class WeiboLoginScanQrCode(WeiboLogin):

    def _initialize_http(self):
        super()._initialize_http()
        self._qrimg_url = "https://login.sina.com.cn/sso/qrcode/image?entry=sinawap&size=180&callback=STK_{}"
        self._check_qrcode_url = "https://login.sina.com.cn/sso/qrcode/check?entry=sinawap&qrid={}&callback=STK_{}"
        self._cross_domain_url = "https://login.sina.com.cn/sso/login.php?entry=sinawap&returntype=TEXT&crossdomain=1" \
                                 "&cdult=3&domain=weibo.com&alt={}&savestate=30&callback=STK_{} "

    def is_login(self):
        response = self.session.get(self._test_login_url, allow_redirects=False)
        return response.status_code == 200

    def _download_qr_image(self) -> tuple:
        """
        :return: (???????????????????????????, qrid)
        """
        response = self.session.get(self._qrimg_url.format(int(time.time() * 1000)))
        data = utils.jsoncallback_str2json(response.text)['data']
        qrid = data['qrid']
        res = self.session.get(data['image'])
        file = os.path.join(os.path.expanduser('~'), hashlib.md5(str(time.time()).encode()).hexdigest() + ".png")
        Path(file).write_bytes(res.content)
        return file, qrid

    def _wait_for_scan(self, file: str, qrid: str) -> str:
        """
        :param file: ??????????????????
        :param qrid: qrid
        :return: ?????????alt
        """
        command = f'start "Pillow" /WAIT "{file}" && ping -n 2 127.0.0.1 >NUL && del /f "{file}"'
        os.system(command)

        alt = ""
        while True:
            res = self.session.get(self._check_qrcode_url.format(qrid, int(time.time() * 1000)))
            res_json = utils.jsoncallback_str2json(res.text)
            if res_json['retcode'] == 50114003:
                self._logger.warning(res_json['msg'])
                break

            if res_json['retcode'] == 20000000:
                self._logger.info("????????????!")
                alt = res_json["data"]["alt"]
                break

            time.sleep(1)

        if not alt:
            self._logger.error("????????????!")
            exit(0)

        return alt

    def _do_login(self) -> None:
        """
        :return: ??????????????????
        """
        file, qrid = self._download_qr_image()
        alt = self._wait_for_scan(file, qrid)
        response = self.session.get(self._cross_domain_url.format(alt, int(time.time() * 1000)))

        data = utils.jsoncallback_str2json(response.text)
        cross_domain_urls, uid, nick = data["crossDomainUrlList"], data['uid'], data['nick']
        for url in cross_domain_urls:
            self.session.get(url)

        self._cross_domain()

        self._logger.debug("login successfully cookies:")
        for k in self.session.cookies:
            self._logger.debug(f"{k.name} = {k.value}, {k.domain}")

        self.session.headers["traceparent"] = "00-46d545e2f58917a67fed36addafd5996-7072876a58e5ea30-00"
        self.session.headers['x-xsrf-token'] = self.session.cookies.get('XSRF-TOKEN')

        if self.is_login():
            self._logger.info(f"uid: {uid}, nickname: {nick}, ????????????!")
            raise LoginFailedException


if __name__ == '__main__':
    # s = RedisSessionManager("18280484271")
    # session = WeiboLoginScanQrCode(session_manager=None, log_level=logging.DEBUG).login()
    session = WeiboLoginVerifyCode('1,', '2', log_level=logging.DEBUG)
    # session = requests.Session()
    # session.cookies.set("a", "b", domain="weibo.com")
    # session.cookies.set("a", "c", domain="zhihu.com")
    # print(session.cookies.get("a", domain="zhihu.com"))
