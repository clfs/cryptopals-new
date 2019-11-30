# 8. Detect AES in ECB mode
from typing import List, Optional

from Cryptodome.Cipher import AES

import lib.iteration as iteration


def is_aes_ecb_ct(x: bytes) -> bool:
    blocks = iteration.blocks(x, AES.block_size)
    return len(blocks) > len(set(blocks))  # True if repeated block


def find_aes_ecb_ct(cts: List[bytes]) -> Optional[bytes]:
    return next((ct for ct in cts if is_aes_ecb_ct(ct)), None)


def test_solution():
    with open("data/08.txt") as f:
        cts = [bytes.fromhex(line) for line in f]

    want = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    got = find_aes_ecb_ct(cts).hex()
    assert want == got
