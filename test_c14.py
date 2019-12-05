# 14. Byte-at-a-time ECB decryption (Harder)
import statistics

from Cryptodome.Cipher import AES

import lib.iteration as iteration
import lib.oracles as oracles


def find_prefix_len(oracle: oracles.AffixEcb) -> int:
    # Create a "magic" block that decrypts to a block of null bytes. Then,
    # submit queries until the magic block shows up - once it does, you can
    # calculate the prefix length.
    response = oracle.response(bytes(3 * AES.block_size))
    magic = statistics.mode(iteration.blocks(response, AES.block_size))  # type: ignore

    for query_len in range(AES.block_size, 2 * AES.block_size):
        query = bytes(query_len)
        response = oracle.response(query)
        blocks = iteration.blocks(response, AES.block_size)
        try:
            return AES.block_size * (blocks.index(magic) + 1) - query_len
        except ValueError:  # Magic block wasn't found.
            continue
    raise RuntimeError("prefix length not found")


def find_suffix_len(oracle: oracles.AffixEcb, prefix_len: int) -> int:
    reference_len = len(oracle.response(b""))
    for query_len in range(1, AES.block_size + 1):
        query = bytes(query_len)
        response = oracle.response(query)
        if len(response) > reference_len:
            return reference_len - prefix_len - query_len
    raise RuntimeError("suffix length not found")


def find_suffix(oracle: oracles.AffixEcb) -> bytes:
    # Save some time and skip the block size / cipher mode calculations from
    # challenge 12. Just assume the attacker already knows it's AES-ECB.
    prefix_len = find_prefix_len(oracle)
    suffix_len = find_suffix_len(oracle, prefix_len)

    answer = b""
    for _ in range(suffix_len):
        padding_len = (AES.block_size - len(answer) - prefix_len - 1) % AES.block_size
        padding = bytes(padding_len)
        reference = oracle.response(padding)
        for n in range(256):
            query = padding + answer + bytes([n])
            response = oracle.response(query)
            match_until = prefix_len + len(query)
            if response[:match_until] == reference[:match_until]:
                answer += bytes([n])
                break
    return answer


def test_solution() -> None:
    oracle = oracles.AffixEcb()
    for _ in range(5):
        oracle.reset()
        assert find_suffix(oracle) == oracle.suffix
