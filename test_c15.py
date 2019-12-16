# 15. PKCS#7 padding validation
from typing import Optional

from Cryptodome.Util import Padding


def test_solution() -> None:
    cases = [
        (b"ICE ICE BABY\x04\x04\x04\x04", b"ICE ICE BABY"),
        (b"ICE ICE BABY\x05\x05\x05\x05", None),
        (b"ICE ICE BABY\x01\x02\x03\x04", None),
    ]
    for s, want in cases:
        try:
            got: Optional[bytes] = Padding.unpad(s, len(s))
        except ValueError:
            got = None
        assert got == want
