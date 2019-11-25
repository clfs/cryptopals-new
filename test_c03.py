#!/usr/bin/env python3
# 3. Single-byte XOR cipher

import lib.bitops as bitops
import lib.ciphers as ciphers


def find_key(ct: bytes) -> int:
    # We can get away with a cheap heuristic because the cipher is simple.
    def heuristic(k: int) -> int:
        return bitops.xor_single(ct, k).count(b" ")

    return max(range(256), key=heuristic)


def test_solution():
    ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    pt = b"Cooking MC's like a pound of bacon"

    key = find_key(bytes.fromhex(ct))
    pt_found = ciphers.SingleXorCipher(key).decrypt(bytes.fromhex(ct))
    assert pt_found == pt
