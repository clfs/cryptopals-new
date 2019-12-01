import base64
from typing import Dict


def hex_to_base64(s: str) -> bytes:
    return base64.b64encode(bytes.fromhex(s))


def key_value_parse(s: str) -> Dict[str, str]:
    # >>> key_value_parse('month=april&year=1975')
    # {'month': 'april', 'year': '1975'}
    d = {}
    for pair in s.split("&"):
        k, v = pair.split("=")
        d[k] = v
    return d
