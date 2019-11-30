import Cryptodome.Util.Padding as Padding


def test_solution():
    a = b"YELLOW SUBMARINE"
    b = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    assert Padding.pad(a, 20) == b
