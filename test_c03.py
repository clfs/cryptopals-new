#!/usr/bin/env python3
# 3. Single-byte XOR cipher

import Cryptodome.Util.strxor as strxor

import lib.ciphers as ciphers


def heuristic(pt: bytes) -> int:
    # We can get away with a cheap heuristic because the cipher is simple.
    return pt.count(b" ")


def find_pt(ct: bytes) -> bytes:
    pts = (strxor.strxor_c(ct, k) for k in range(256))
    return max(pts, key=heuristic)


def test_solution():
    ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    pt = b"Cooking MC's like a pound of bacon"

    assert find_pt(bytes.fromhex(ct)) == pt
