# Attackers are PERMITTED to:
# - call any service method not prefixed by an underscore
# Attackers are PROHIBITED from:
# - instantiating additional services beyond the one(s) provided
# - manually getting/setting service attributes, regardless of underscores
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
