"""
 author rufeng
 date 2021/11/12/11:39
 description 
"""
import json
import re


def jsoncallback_str2json(text: str) -> dict:
    return json.loads(re.search(r"\(({.*?})\)", text).group(1))
