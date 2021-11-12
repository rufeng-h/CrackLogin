"""
 author rufeng
 date 2021/11/12/11:37
 description 
"""
import copy
import hashlib
import json
import os
import re
import time
from pathlib import Path

import log
import utils
from login.base import Login
from session.manager import SessionManager, RedisSessionManager


class WeiboLoginScanQrCode(Login):
    def __init__(self, session_manager: SessionManager = None, **kwargs):
        """
        :param session_manager: SessionManager
        :param kwargs: kwargs for session_manager load_sesson method
        """
        super().__init__(session_manager=session_manager, **kwargs)
        self._logger = log.get_logger(self.__class__.__name__)
        self._initialize_http()

    def _initialize_http(self):
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
        self.session.headers.update(headers)
        self._verify_login_url = "https://security.weibo.com/account/security"
        self._qrimg_url = "https://login.sina.com.cn/sso/qrcode/image?entry=sinawap&size=180&callback=STK_{}"
        self._check_qrcode_url = "https://login.sina.com.cn/sso/qrcode/check?entry=sinawap&qrid={}&callback=STK_{}"
        self._succ_url = "https://weibo.com/newlogin?tabtype=weibo&gid=102803&url=https%3A%2F%2Fweibo.com%2F"
        self._cross_domain_url = "https://login.sina.com.cn/sso/login.php?entry=sinawap&returntype=TEXT&crossdomain=1" \
                                 "&cdult=3&domain=weibo.com&alt={}&savestate=30&callback=STK_{} "

    def is_login(self):
        response = self.session.get(self._verify_login_url, allow_redirects=False)
        return response.status_code == 200

    def _download_qr_image(self) -> tuple:
        """
        :return: (二维码图片绝对路径, qrid)
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
        :param file: 图片绝对路径
        :param qrid: qrid
        :return: 登录的alt
        """
        command = f'start "Pillow" /WAIT "{file}" && ping -n 2 127.0.0.1 >NUL && del /f "{file}"'
        os.system(command)

        alt = ""
        while True:
            res = self.session.get(self._check_qrcode_url.format(qrid, int(time.time() * 1000)))
            res_json = json.loads(re.search(r"\(({.*?})\)", res.text).group(1))
            if res_json['retcode'] == 50114003:
                self._logger.warning(res_json['msg'])
                break

            if res_json['retcode'] == 20000000:
                self._logger.info("扫码成功!")
                alt = res_json["data"]["alt"]
                break

            time.sleep(1)

        if not alt:
            self._logger.error("登录失败!")
            exit(0)

        return alt

    def login(self):
        """
        :return: 登录成功的session
        """
        if self.is_login():
            self._logger.info("cookie有效!")
            return self.session

        self._logger.info("不存在cookie或cookie过时!，重新登录!")
        file, qrid = self._download_qr_image()
        alt = self._wait_for_scan(file, qrid)
        response = self.session.get(self._cross_domain_url.format(alt, int(time.time() * 1000)))

        data = utils.jsoncallback_str2json(response.text)
        cross_domain_urls, uid, nick = data["crossDomainUrlList"], data['uid'], data['nick']
        for url in cross_domain_urls:
            self.session.get(url)

        self._cross_domain()
        self.session.get(self._succ_url)

        self.session.headers["traceparent"] = "00-46d545e2f58917a67fed36addafd5996-7072876a58e5ea30-00"
        self.session.headers['x-xsrf-token'] = self.session.cookies.get('XSRF-TOKEN')

        if self.is_login():
            self._logger.info(f"uid: {uid}, nickname: {nick}, 登录成功!")
        else:
            self._logger.error("登录失败!，未知错误")

        self.session_manager.store_session(self.session)

        return self.session

    def _cross_domain(self):
        """
        默认cookie是.login.sina.com，我们设置成所有网站
        :return:
        """
        cookies = copy.deepcopy(self.session.cookies)
        for k, v in cookies.items():
            self.session.cookies.set(k, v)


if __name__ == '__main__':
    # s = RedisSessionManager("18280484271")
    session = WeiboLoginScanQrCode(session_manager=None).login()
