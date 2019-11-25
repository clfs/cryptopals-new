import Cryptodome.Util.strxor as strxor

import itertools


def xor_hex(a: str, b: str) -> str:
    """XOR two hex-encoded strings together."""
    return strxor.strxor(bytes.fromhex(a), bytes.fromhex(b)).hex()


def xor_repeat(a: bytes, b: bytes) -> bytes:
    """XOR a bytestring with a repeating bytestring."""
    return bytes(x ^ y for x, y in zip(a, itertools.cycle(b)))
