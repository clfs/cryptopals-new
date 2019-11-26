import Cryptodome.Util.strxor as strxor


def find_single_xor_key(ct: bytes) -> int:
    common_chars = set(b" etaoin")

    def heuristic(k: int) -> int:
        # 1 point for every common character in the resulting plaintext.
        return sum(1 for b in strxor.strxor_c(ct, k) if b in common_chars)

    return max(range(256), key=heuristic)
