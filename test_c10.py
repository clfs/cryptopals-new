import base64

from Cryptodome.Cipher import AES

import lib.ciphers as ciphers


def test_solution():
    with open("data/10.txt") as f:
        ct = base64.b64decode(f.read())
    key, iv = b"YELLOW SUBMARINE", bytes(AES.block_size)

    pt = ciphers.AesCbc(key).decrypt(ct, iv)
    print(pt.decode())
