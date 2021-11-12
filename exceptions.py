"""
 author rufeng
 date 2021/11/12/20:51
 description 
"""
from requests import Response


class UnexpectedResponseException(Exception):
    def __init__(self, response: Response, *args, ):
        self._response = response
        super(UnexpectedResponseException, self).__init__(*args)

    def __str__(self) -> str:
        return super().__str__()


class LoginFailedException(Exception):
    pass
