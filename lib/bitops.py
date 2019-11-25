import itertools


def xor(a: bytes, b: bytes) -> bytes:
    """XOR two bytestrings together."""
    # The result is as long as the shorter of the two inputs.
    ret = bytearray(a)
    for i, v in enumerate(b):
        ret[i] ^= v
    return bytes(ret)


def xor_hex(a: str, b: str) -> str:
    """XOR two hex-encoded strings together."""
    # The result is as long as the shorter of the two inputs.
    return xor(bytes.fromhex(a), bytes.fromhex(b)).hex()


def xor_single(a: bytes, b: int) -> bytes:
    """XOR a bytestring with a single integer."""
    ret = bytearray(a)
    for i in range(len(ret)):
        ret[i] ^= b
    return bytes(ret)
