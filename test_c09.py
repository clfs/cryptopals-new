"""9. Implement PKCS#7 padding."""
import Cryptodome.Util.Padding as Padding


def test_solution() -> None:
    a = b"YELLOW SUBMARINE"
    b = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    assert Padding.pad(a, 20) == b
