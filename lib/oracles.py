# Attackers are PERMITTED to:
# - call any oracle method not prefixed by an underscore
# Attackers are PROHIBITED from:
# - instantiating additional oracles beyond the one(s) provided
# - manually getting/setting oracle attributes, regardless of underscores
import base64
import secrets

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


class PaddingCbc:
    def __init__(self) -> None:
        self.cbc = self._rand_cbc()
        self.secrets = [
            base64.b64decode(s)
            for s in """
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
""".split()
        ]

    @staticmethod
    def _rand_cbc() -> ciphers.AesCbc:
        return ciphers.AesCbc(rng.secure_bytes(16))

    def _reset(self) -> None:
        """Reset the oracle so that it can be reused for testing."""
        self.cbc = self._rand_cbc()

    def create_token(self) -> bytes:
        iv, pt = rng.secure_bytes(16), secrets.choice(self.secrets)
        return iv + self.cbc.encrypt(pt, iv)

    def response(self, query: bytes) -> bool:
        """Raise ValueError if the query's padding is invalid."""
        iv, ct = query[: AES.block_size], query[AES.block_size :]
        try:
            _ = self.cbc.decrypt(ct, iv)
        except ValueError:
            return False
        return True
