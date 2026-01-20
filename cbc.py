from Crypto.Util import number
import random 
import rsa_core


# RSA is not a block cipher and CBC mode is not used in real-world cryptosystems.
# testing of the key generation algorithm


# CONVERTING THE DATA INTO BLOCKS
def generate_iv(block_size: int) -> int:
    min_val = 0
    max_val = 2 ** (block_size * 8) - 1
    return random.randint(min_val, max_val)


def xor_int(a: int, b: int) -> int:
    return a ^ b

def rsa_cbc_encrypt(blocks: list[int], e: int, n: int, iv: int, block_size: int) -> list[int]:
    encrypted_blocks = []
    mask = (1 << (block_size * 8)) - 1

    prev = iv & mask

    for block in blocks:
        mixed = block ^ prev
        encrypted_block = rsa_core.rsa_encrypt_block(mixed, e, n)
        encrypted_blocks.append(encrypted_block)
        prev = encrypted_block & mask # important

    return encrypted_blocks


def rsa_cbc_decrypt(encrypted_blocks: list[int], d: int, n: int, iv: int, block_size: int) -> list[int]:
    blocks = []
    mask = (1 << (block_size * 8)) - 1

    prev = iv & mask

    for encrypted_block in encrypted_blocks:
        mixed = rsa_core.rsa_decrypt_block(encrypted_block, d, n)
        mixed &= mask # importatn
        block = mixed ^ prev
        blocks.append(block)
        prev = encrypted_block & mask # important

    return blocks


def encrypt_text(text: str, e: int, n: int, block_size: int):
    rsa_core.validate_block_size(block_size, n)
    blocks = rsa_core.string_to_blocks(text, block_size)
    iv = generate_iv(block_size)

    encrypted_blocks = rsa_cbc_encrypt(blocks, e, n, iv, block_size)  # FIX
    return iv, encrypted_blocks


def decrypt_text(encrypted_blocks, d, n, iv, block_size):
    blocks = rsa_cbc_decrypt(encrypted_blocks, d, n, iv, block_size)
    return rsa_core.blocks_to_string(blocks, block_size)
