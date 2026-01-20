import rsa_core

def rsa_ecb_encrypt(blocks: list[int], e: int, n: int) -> list[int]:
    """Encrypt blocks independently (ECB mode)."""
    return [rsa_core.rsa_encrypt_block(block, e, n) for block in blocks]


def rsa_ecb_decrypt(encrypted_blocks:  list[int], d: int, n: int) -> list[int]:
    """Decrypt blocks independently (ECB mode)."""
    return [rsa_core.rsa_decrypt_block(block, d, n) for block in encrypted_blocks]


def encrypt_text(text: str, e: int, n: int, block_size: int) -> list[int]:
    rsa_core.validate_block_size(block_size, n)
    blocks = rsa_core.string_to_blocks(text, block_size)
    return rsa_ecb_encrypt(blocks, e, n)


def decrypt_text(encrypted_blocks:  list[int], d: int, n: int, block_size:  int) -> str:
    blocks = rsa_ecb_decrypt(encrypted_blocks, d, n)
    return rsa_core.blocks_to_string(blocks, block_size)