import random 
import rsa_core

# NOTE RSA is not a block cipher and CBC mode is not used in real-world cryptosystems.

# ENCRYPTING THE DATA IN CBC MODE
def generate_iv(block_size: int) -> int:
    """
    :param block_size: Block size in bytes.
    :type block_size: int
    :return: Initialisation vector "iv" used as c_0 in cipher-block chaining.
    :rtype: int
    """
    min_val = 0
    max_val = 2 ** (block_size * 8) - 1
    return random.randint(min_val, max_val)


def xor_int(a: int, b: int) -> int:
    """
    Performs a bitwise XOR operation on two integers.

    :param a: First operand.
    :type a: int
    :param b: Second operand.
    :type b: int
    :return: Result of a XOR b.
    :rtype: int
    """
    return a ^ b

def rsa_cbc_encrypt(blocks: list[int], e: int, n: int, iv: int, block_size: int) -> list[int]:
    """
    Encrypts a list of blocks (integers) using RSA encryption in CBC mode. 
    
    :param blocks: Blocks to be encrypted.
    :type blocks: list[int]
    :param e: Public key.
    :type e: int
    :param n: RSA modulus.
    :type n: int
    :param iv: Initialisation vector.
    :type iv: int
    :param block_size: Size of blocks (in bytes).
    :type block_size: int
    :return: Encrypted blocks.
    :rtype: list[int]
    """
    encrypted_blocks = []
    mask = (1 << (block_size * 8)) - 1

    prev = iv & mask

    for block in blocks:
        mixed = block ^ prev
        encrypted_block = rsa_core.rsa_encrypt_block(mixed, e, n)
        encrypted_blocks.append(encrypted_block)
        prev = encrypted_block & mask

    return encrypted_blocks


def rsa_cbc_decrypt(encrypted_blocks: list[int], d: int, n: int, iv: int, block_size: int) -> list[int]:
    """
    Decrypts a list of blocks (integers) using RSA encryption in CBC mode. 
    
    :param encrypted_blocks: Blocks to be decrypted.
    :type encrypted_blocks: list[int]
    :param d: Private key.
    :type d: int
    :param n: RSA modulus.
    :type n: int
    :param iv: Initialisation vector.
    :type iv: int
    :param block_size: Size of blocks (in bytes).
    :type block_size: int
    :return: Decrypted blocks.
    :rtype: list[int]
    """
    blocks = []
    mask = (1 << (block_size * 8)) - 1

    prev = iv & mask

    for encrypted_block in encrypted_blocks:
        mixed = rsa_core.rsa_decrypt_block(encrypted_block, d, n)
        mixed &= mask 
        block = mixed ^ prev
        blocks.append(block)
        prev = encrypted_block & mask

    return blocks


def encrypt_text(text: str, e: int, n: int, block_size: int) -> tuple[int, list[int]]:
    """
    Encrypts a given text using RSA encryption in CBC mode.
    
    :param text: Text to be encrypted.
    :type text: str
    :param e: Public key.
    :type e: int
    :param n: RSA modulus
    :type n: int
    :param block_size: Size of blocks (in bytes).
    :type block_size: int
    :return: Initialization vector and encrypted blocks.
    :rtype: tuple[int, list[int]]
    """
    rsa_core.validate_block_size(block_size, n)
    blocks = rsa_core.string_to_blocks(text, block_size)
    iv = generate_iv(block_size)

    encrypted_blocks = rsa_cbc_encrypt(blocks, e, n, iv, block_size)
    return iv, encrypted_blocks


def decrypt_text(encrypted_blocks: list[int], d: int, n: int, iv: int, block_size: int) -> str:
    """
    Decrypts encrypted blocks using RSA encryption in CBC mode back into text.
    
    :param encrypted_blocks: Encrypted blocks.
    :type encrypted_blocks: list[int]
    :param d: Private key.
    :type d: int
    :param n: RSA modulus.
    :type n: int
    :param iv: Initialisation vector.
    :type iv: int
    :param block_size: Size of blocks (in bytes).
    :type block_size: int
    :return: Decrypted text.
    :rtype: str
    """
    blocks = rsa_cbc_decrypt(encrypted_blocks, d, n, iv, block_size)
    return rsa_core.blocks_to_string(blocks, block_size)
