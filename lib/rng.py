import secrets
from typing import List


def secure_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def secure_int_between(a: int, b: int) -> int:
    # a <= result <= b.
    return a + secrets.randbelow(b - a + 1)


def secure_bool() -> bool:
    return bool(secrets.randbits(1))


def secure_choice(x: List[bytes]) -> bytes:
    return secrets.choice(x)
