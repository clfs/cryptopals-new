from collections import Counter
from typing import Iterable, Optional, TypeVar

from Cryptodome.Cipher import AES

import lib.iteration as iteration

T = TypeVar("T")


def is_aes_ecb_ct(x: Optional[bytes]) -> bool:
    if x is None:
        return False
    blocks = iteration.blocks(x, AES.block_size)
    return len(blocks) > len(set(blocks))  # True if repeated block


def mode(it: Iterable[T]) -> T:
    # If there's more than one mode, return an arbitrary one.
    return Counter(it).most_common(1)[0][0]
