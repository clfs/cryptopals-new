from typing import List

import Cryptodome.Util.strxor as strxor


def find_pt(cts: List[bytes]) -> bytes:
    def heuristic(pt: bytes) -> int:
        # 1 point for every character in " etaoin"; higher is better.
        score, good = 0, set(b" etaoin")
        for b in pt:
            if b in good:
                score += 1
        return score

    pts = (strxor.strxor_c(ct, k) for ct in cts for k in range(256))
    return max(pts, key=heuristic)


def test_solution():
    with open("data/04.txt") as f:
        cts = [bytes.fromhex(line) for line in f]
    assert find_pt(cts) == b"Now that the party is jumping\n"
