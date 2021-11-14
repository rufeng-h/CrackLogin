"""
 author rufeng
 date 2021/11/12/11:39
 description 
"""
import json
import random
import re
import string

CHARS = string.ascii_letters + string.digits


def jsoncallback_str2json(text: str) -> dict:
    return json.loads(re.search(r"\(({.*?})\)", text).group(1))


def random_ascii(cnt: int = 16) -> str:
    return ''.join(random.choices(CHARS, k=cnt))


if __name__ == '__main__':
    csrf = ""
    print(f'{{\"s\":\"王菲\",\"limit\":\"8\",\"csrf_token\":\"{csrf}\"}}')
