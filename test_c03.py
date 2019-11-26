# 3. Single-byte XOR cipher

import Cryptodome.Util.strxor as strxor

import lib.ciphers as ciphers
import lib.attacks as attacks


def test_solution():
    ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    pt = b"Cooking MC's like a pound of bacon"

    ct_bytes = bytes.fromhex(ct)
    key = attacks.find_single_xor_key(ct_bytes)
    assert ciphers.SingleXor(key).decrypt(ct_bytes) == pt
