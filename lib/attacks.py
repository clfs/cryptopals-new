import Cryptodome.Util.strxor as strxor

import lib.bitops as bitops
import lib.reshape as reshape


def find_single_xor_key(ct: bytes) -> int:
    common_chars = set(b" etaoin")

    def heuristic(k: int) -> int:
        # 1 point for every common character in the resulting plaintext.
        return sum(1 for b in strxor.strxor_c(ct, k) if b in common_chars)

    return max(range(256), key=heuristic)


def find_repeating_xor_key(
    ct: bytes, lower_bound: int = 2, upper_bound: int = 40
) -> bytes:
    def find_key_size(ct: bytes) -> int:
        def heuristic(key_size: int) -> int:
            # The sum of Hamming distances between consecutive key-sized chunks.
            pairs = reshape.pairs(reshape.blocks(ct, key_size))
            return sum(bitops.hamming_dist(x, y) for x, y in pairs if len(x) == len(y))

        return min(range(lower_bound, upper_bound + 1), key=heuristic)

    key_size = find_key_size(ct)
    return bytes(
        find_single_xor_key(ct[offset::key_size]) for offset in range(key_size)
    )
