# 6. Break repeating-key XOR
import base64

import lib.attacks as attacks
import lib.ciphers as ciphers


def test_solution():
    with open("data/06.txt") as f:
        ct = base64.b64decode(f.read())

    key = attacks.find_repeating_xor_key(ct)
    pt = ciphers.RepeatingXor(key).decrypt(ct)
    print(pt.decode())
