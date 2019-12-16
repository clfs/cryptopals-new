# 16. CBC bitflipping attacks
from Cryptodome.Cipher import AES

import lib.bitops as bitops
import lib.services as services


def create_admin_token(manager: services.CbcTokenManager) -> bytes:
    token = manager.token_for(bytes(16).decode())
    iv, ct = token[: AES.block_size], token[AES.block_size :]
    offset = len("comment1=cooking%20MCs;userdata=") - AES.block_size
    return iv + bitops.xor_at_offset(ct, b";admin=true;", offset)


def test_solution() -> None:
    manager = services.CbcTokenManager()
    token = create_admin_token(manager)
    assert manager.is_admin(token)
