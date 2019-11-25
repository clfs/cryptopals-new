#!/usr/bin/env python3
# 1. Convert hex to base64

import lib.encoding as encoding


def test_solution():
    a = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    assert encoding.hex_to_base64(a) == b
