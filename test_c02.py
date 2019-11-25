# 2. Fixed XOR

import lib.bitops as bitops


def test_solution():
    a = "1c0111001f010100061a024b53535009181c"
    b = "686974207468652062756c6c277320657965"
    c = "746865206b696420646f6e277420706c6179"

    assert bitops.xor_hex(a, b) == c
