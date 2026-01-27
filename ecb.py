import rsa_core

def rsa_ecb_encrypt(blocks: list[int], e: int, n: int) -> list[int]:
    """Encrypt blocks independently (ECB mode)."""
    encrypted = []
    for block in blocks:
        print(f"[ECB-ENCRYPT] Plaintext block = {block}")
        c = rsa_core.rsa_encrypt_block(block, e, n)
        print(f"[ECB-ENCRYPT] Ciphertext block = {c}")
        encrypted.append(c)

    print("[ECB-ENCRYPT] ECB encryption complete\n")
    return encrypted


def rsa_ecb_decrypt(encrypted_blocks:  list[int], d: int, n: int) -> list[int]:
    """Decrypt blocks independently (ECB mode)."""
    print("[ECB-DECRYPT] Starting ECB decryption")

    blocks = []
    for block in encrypted_blocks:
        print(f"[ECB-DECRYPT] Ciphertext block = {block}")
        m = rsa_core.rsa_decrypt_block(block, d, n)
        print(f"[ECB-DECRYPT] Plaintext block = {m}")
        blocks.append(m)

    print("[ECB-DECRYPT] ECB decryption complete\n")
    return blocks


def encrypt_text(text: str, e: int, n: int, block_size: int) -> list[int]:
    print("[ECB] Encrypting full text in ECB mode")
    print(f"[ECB] Block size = {block_size} bytes")

    rsa_core.validate_block_size(block_size, n)
    blocks = rsa_core.string_to_blocks(text, block_size)
    
    r = rsa_ecb_encrypt(blocks, e, n)
    print(f"[ECB] Encrypted blocks:\n{r}\n")

    return r 


def decrypt_text(encrypted_blocks:  list[int], d: int, n: int, block_size:  int) -> str:
    print("[ECB] Decrypting full ciphertext in ECB mode")
    blocks = rsa_ecb_decrypt(encrypted_blocks, d, n)
    return rsa_core.blocks_to_string(blocks, block_size)
    print("[ECB] ECB decryption finished\n")
