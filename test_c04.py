# 4. Detect single-character XOR
from typing import List

import Cryptodome.Util.strxor as strxor


def heuristic(pt: bytes) -> int:
    # Cheaper heuristic.
    return pt.count(b" ") + pt.count(b"e")


def find_pt(cts: List[bytes]) -> bytes:
    pts = (strxor.strxor_c(ct, k) for ct in cts for k in range(256))
    return max(pts, key=heuristic)


def test_solution():
    with open("data/04.txt") as f:
        cts = [bytes.fromhex(line) for line in f]

    assert find_pt(cts) == b"Now that the party is jumping\n"
