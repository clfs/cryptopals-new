# 13. ECB cut-and-paste
from Cryptodome.Cipher import AES
import Cryptodome.Util.Padding as Padding

import lib.services as services


def create_admin_profile(manager: services.EcbProfileManager) -> bytes:
    # Assume the attacker knows:
    # 1. AES encryption is being used.
    # 2. The profile format is email=foo@bar.com&uid=10&role=user.
    #
    # This isn't really a common scenario, but it saves a lot of boilerplate
    # around brute-forcing block sizes and offsets. I think this is what the
    # authors probably intended.
    magic_block = Padding.pad(b"admin", AES.block_size).decode()
    email1 = "A" * (AES.block_size - len("email=")) + magic_block
    email2 = "A" * (2 * AES.block_size - len("email=") - len("&uid=10&role="))
    profile1 = manager.profile_for(email1)
    profile2 = manager.profile_for(email2)
    # This is the cut-and-paste step.
    return profile2[: -AES.block_size] + profile1[AES.block_size : 2 * AES.block_size]


def test_solution() -> None:
    manager = services.EcbProfileManager()
    profile = create_admin_profile(manager)
    assert manager.get_role(profile) == "admin"
