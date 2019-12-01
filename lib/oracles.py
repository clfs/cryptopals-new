from Cryptodome.Cipher import AES

import lib.ciphers as ciphers
import lib.rng as rng


class EcbOrCbc:
    def __init__(self):
        self._last_mode = None

    @staticmethod
    def _junk() -> bytes:
        return rng.secure_bytes(rng.secure_int_between(5, 10))

    def query(self, msg: bytes) -> bytes:
        pt = self._junk() + msg + self._junk()
        key = rng.secure_bytes(16)
        if rng.secure_bool():
            self._last_mode = "ECB"
            ct = ciphers.AesEcb(key).encrypt(pt)
        else:
            self._last_mode = "CBC"
            iv = rng.secure_bytes(AES.block_size)
            ct = ciphers.AesCbc(key).encrypt(pt, iv)
        return ct
