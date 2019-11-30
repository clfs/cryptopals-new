from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding
import Cryptodome.Util.strxor as strxor

import lib.bitops as bitops
import lib.iteration as iteration


class SingleXor:
    def __init__(self, k: int):
        self.k = k

    def _crypt(self, t: bytes) -> bytes:
        return strxor.strxor_c(t, self.k)

    def encrypt(self, pt: bytes) -> bytes:
        return self._crypt(pt)

    def decrypt(self, ct: bytes) -> bytes:
        return self._crypt(ct)


class RepeatingXor:
    def __init__(self, k: bytes):
        self.k = k

    def _crypt(self, t: bytes) -> bytes:
        return bitops.xor_repeat(t, self.k)

    def encrypt(self, pt: bytes) -> bytes:
        return self._crypt(pt)

    def decrypt(self, ct: bytes) -> bytes:
        return self._crypt(ct)


class AesEcb:
    def __init__(self, k: bytes):
        self.ecb = AES.new(k, AES.MODE_ECB)

    @staticmethod
    def _pad(pt: bytes) -> bytes:
        return Padding.pad(pt, AES.block_size)

    @staticmethod
    def _unpad(ct: bytes) -> bytes:
        return Padding.unpad(ct, AES.block_size)

    def encrypt(self, pt: bytes) -> bytes:
        return self.ecb.encrypt(self._pad(pt))

    def decrypt(self, ct: bytes) -> bytes:
        return self._unpad(self.ecb.decrypt(ct))


class AesCbc:
    def __init__(self, k: bytes):
        self.ecb = AES.new(k, AES.MODE_ECB)

    @staticmethod
    def _pad(pt: bytes) -> bytes:
        return Padding.pad(pt, AES.block_size)

    @staticmethod
    def _unpad(ct: bytes) -> bytes:
        return Padding.unpad(ct, AES.block_size)

    def encrypt(self, pt: bytes, iv: bytes) -> bytes:
        p = iteration.blocks(self._pad(pt), AES.block_size)
        c = [iv]
        for x, y in zip(p, c):
            c.append(self.ecb.encrypt(strxor.strxor(x, y)))
        return b"".join(c[1:])  # Drop the IV we started with.

    def decrypt(self, ct: bytes, iv: bytes) -> bytes:
        c = [iv] + iteration.blocks(ct, AES.block_size)
        p = [strxor.strxor(x, self.ecb.decrypt(y)) for x, y in iteration.pairs(c)]
        return self._unpad(b"".join(p))
