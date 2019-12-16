from typing import Optional

from Cryptodome.Cipher import AES

import lib.iteration as iteration


def is_aes_ecb_ct(x: Optional[bytes]) -> bool:
    if x is None:
        return False
    blocks = iteration.blocks(x, AES.block_size)
    return len(blocks) > len(set(blocks))  # True if repeated block
