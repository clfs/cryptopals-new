"""Various compromisable services.

Attackers are PERMITTED to:
- call any service method not prefixed by an underscore

Attackers are PROHIBITED from:
- instantiating additional services beyond the one(s) provided
- manually getting/setting service attributes, regardless of underscores
"""
from Cryptodome.Cipher import AES

import lib.ciphers as ciphers
import lib.encoding as encoding
import lib.rng as rng


class EcbProfileManager:
    def __init__(self) -> None:
        self.ecb = ciphers.AesEcb(rng.secure_bytes(16))

    def profile_for(self, email: str) -> bytes:
        if "@" in email or "=" in email:
            raise ValueError("invalid email address")
        profile_str = f"email={email}&uid=10&role=user"
        return self.ecb.encrypt(profile_str.encode())

    def get_role(self, profile: bytes) -> str:
        profile_str = self.ecb.decrypt(profile).decode()
        return encoding.key_value_parse(profile_str)["role"]


class CbcTokenManager:
    def __init__(self) -> None:
        self.cbc = ciphers.AesCbc(rng.secure_bytes(16))
        self.token_format = "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon"

    def token_for(self, userdata: str) -> bytes:
        if ";" in userdata or "=" in userdata:
            raise ValueError("invalid userdata")
        token = self.token_format.format(userdata).encode()
        iv = rng.secure_bytes(AES.block_size)
        return iv + self.cbc.encrypt(token, iv)

    def is_admin(self, token: bytes) -> bool:
        iv, ct = token[: AES.block_size], token[AES.block_size :]
        return b";admin=true;" in self.cbc.decrypt(ct, iv)
