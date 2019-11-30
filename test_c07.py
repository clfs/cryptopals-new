import base64

import lib.ciphers as ciphers


def test_solution():
    with open("data/07.txt") as f:
        ct = base64.b64decode(f.read())
    key = b"YELLOW SUBMARINE"

    pt = ciphers.AesEcb(key).decrypt(ct)
    print(pt.decode())
