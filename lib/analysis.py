from Cryptodome.Cipher import AES

import lib.iteration as iteration


def is_aes_ecb_ct(x: bytes) -> bool:
    blocks = iteration.blocks(x, AES.block_size)
    return len(blocks) > len(set(blocks))  # True if repeated block
