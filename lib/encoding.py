import base64


def hex_to_base64(s: str) -> bytes:
    return base64.b64encode(bytes.fromhex(s))
