# 12. Byte-at-a-time ECB decryption (Simple)
import functools
import math

import lib.iteration as iteration
import lib.oracles as oracles


def find_block_size(oracle: oracles.SuffixEcb) -> int:
    # Largest possible block size is 128 bytes (Threefish).
    cts = (oracle.response(bytes(n)) for n in range(128))
    # GCD of the ciphertext lengths is the block size.
    return functools.reduce(math.gcd, map(len, cts))


def is_ecb_oracle(oracle: oracles.SuffixEcb, block_size: int) -> bool:
    # I avoided using test_c08.is_aes_ecb_ct(), since the problem *technically*
    # doesn't tell us AES is the cipher used by the oracle.
    query = bytes(block_size * 2)
    blocks = iteration.blocks(oracle.response(query), block_size)
    return len(blocks) > len(set(blocks))  # True if repeated block.


def find_suffix_len(oracle: oracles.SuffixEcb, block_size: int) -> int:
    reference_len = len(oracle.response(b""))
    for query_len in range(1, block_size + 1):
        query = bytes(query_len)
        response = oracle.response(query)
        if len(response) > reference_len:
            return reference_len - query_len
    raise RuntimeError("suffix length not found")


def find_suffix(oracle: oracles.SuffixEcb) -> bytes:
    block_size = find_block_size(oracle)
    assert is_ecb_oracle(oracle, block_size)
    suffix_len = find_suffix_len(oracle, block_size)

    answer = b""
    for _ in range(suffix_len):
        padding = bytes(block_size - (len(answer) % block_size) - 1)
        reference = oracle.response(padding)
        for n in range(256):
            query = padding + answer + bytes([n])
            response = oracle.response(query)
            if response[: len(query)] == reference[: len(query)]:
                answer += bytes([n])
                break
    return answer


def test_solution():
    oracle = oracles.SuffixEcb()

    suffix = find_suffix(oracle)
    assert suffix == oracle.suffix
    print(suffix.decode())
