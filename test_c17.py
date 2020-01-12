# 17. The CBC padding oracle

from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

import lib.iteration as iteration
import lib.oracles as oracles


def custom_xor(a: bytes, b: bytearray, c: bytes) -> bytearray:
    """Custom XOR function to get around mypy; pretty annoying."""
    return bytearray(x ^ y ^ z for x, y, z in zip(a, b, c))


def recover_secret(oracle: oracles.PaddingCbc, token: bytes) -> bytes:
    answer = bytearray()

    for c1, c2 in iteration.pairs(iteration.blocks(token, AES.block_size)):
        p2 = bytearray(AES.block_size)
        for i in reversed(range(AES.block_size)):
            padding = Padding.pad(bytes(i), AES.block_size)
            for guess in range(256):
                p2[i] = guess
                iv = custom_xor(c1, p2, padding)
                # An ugly hack which prevents accidental creation of new, valid
                # padding.
                if i == AES.block_size - 1:
                    iv[: AES.block_size - 2] = bytearray(AES.block_size - 2)
                query = bytes(iv + c2)
                if oracle.response(query):
                    break
        answer += p2

    return Padding.unpad(bytes(answer), AES.block_size)


def test_solution() -> None:
    oracle = oracles.PaddingCbc()
    for _ in range(5):
        token = oracle.create_token()
        secret = recover_secret(oracle, token)
        assert secret in oracle.secrets
        oracle._reset()
