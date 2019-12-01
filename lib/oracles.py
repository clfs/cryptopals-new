# NOTE: All class attributes of oracle instances are considered "inaccessible"
# to the attacker. However, they can be used in automated test cases to confirm
# the attack's success (e.g., EcbOrCbc.last_mode).
import base64

from Cryptodome.Cipher import AES

import lib.ciphers as ciphers
import lib.rng as rng


class EcbOrCbc:
    def __init__(self):
        self.last_mode = None

    @staticmethod
    def _junk() -> bytes:
        return rng.secure_bytes(rng.secure_int_between(5, 10))

    def response(self, query: bytes) -> bytes:
        pt = self._junk() + query + self._junk()
        key = rng.secure_bytes(16)
        if rng.secure_bool():
            self.last_mode = "ECB"
            ct = ciphers.AesEcb(key).encrypt(pt)
        else:
            self.last_mode = "CBC"
            iv = rng.secure_bytes(AES.block_size)
            ct = ciphers.AesCbc(key).encrypt(pt, iv)
        return ct


class SuffixEcb:
    def __init__(self):
        self.ecb = ciphers.AesEcb(rng.secure_bytes(16))
        self.suffix = base64.b64decode(
            """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
        )

    def response(self, query: bytes) -> bytes:
        return self.ecb.encrypt(query + self.suffix)
