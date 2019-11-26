import itertools
from typing import Iterator, List, Tuple


def blocks(x: bytes, n: int) -> List[bytes]:
    # >>> blocks(b'birds', 2)
    # [b'bi', b'rd', b's']
    return [x[i : i + n] for i in range(0, len(x), n)]


def pairs(x: List[bytes]) -> Iterator[Tuple[bytes, bytes]]:
    # >>> for x in r.pairs([b'bat', b'cat', b'rat']):
    # ...     print(x)
    # (b'bat', b'cat')
    # (b'cat', b'rat')
    a, b = itertools.tee(x)
    next(b, None)
    return zip(a, b)
