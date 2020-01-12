"""Bit-level operations."""
import itertools

import Cryptodome.Util.strxor as strxor


def xor_at_offset(a: bytes, b: bytes, n: int) -> bytes:
    """XOR b into a at an offset of n bytes."""
    tmp = bytearray(a)
    for i, v in enumerate(b):
        tmp[i + n] ^= v
    return bytes(tmp)


def xor_hex(a: str, b: str) -> str:
    """XOR two hex-encoded strings together."""
    return strxor.strxor(bytes.fromhex(a), bytes.fromhex(b)).hex()


def xor_repeat(a: bytes, b: bytes) -> bytes:
    """XOR a bytestring with a repeating bytestring."""
    return bytes(x ^ y for x, y in zip(a, itertools.cycle(b)))


def hamming_dist(a: bytes, b: bytes) -> int:
    """Find the bitwise Hamming distance between two bytestrings."""
    return sum(bin(v).count("1") for v in strxor.strxor(a, b))
