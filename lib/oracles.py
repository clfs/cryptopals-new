# Attackers are PERMITTED to:
# - call any oracle method not prefixed by an underscore
# Attackers are PROHIBITED from:
# - instantiating additional oracles beyond the one(s) provided
# - manually getting/setting oracle attributes, regardless of underscores
import base64

from Cryptodome.Cipher import AES

import lib.ciphers as ciphers
import lib.rng as rng


class EcbOrCbc:
    def __init__(self) -> None:
        self.last_mode = ""

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
    def __init__(self) -> None:
        self.ecb = ciphers.AesEcb(rng.secure_bytes(16))
        self.suffix = base64.b64decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        )

    def response(self, query: bytes) -> bytes:
        return self.ecb.encrypt(query + self.suffix)


class AffixEcb:
    def __init__(self) -> None:
        self.ecb = ciphers.AesEcb(rng.secure_bytes(16))
        self.prefix = self._rand_prefix()
        self.suffix = base64.b64decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        )

    @staticmethod
    def _rand_prefix() -> bytes:
        return rng.secure_bytes(rng.secure_int_between(1, 50))

    def reset(self) -> None:
        """Reset the oracle so that it can be reused for testing."""
        self.prefix = self._rand_prefix()

    def response(self, query: bytes) -> bytes:
        return self.ecb.encrypt(self.prefix + query + self.suffix)
