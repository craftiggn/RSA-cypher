from Crypto.Util import number

# KEYGEN
def random_prime(no_bits: int) -> int:
    """
    A function for generating primes of desired length.
    Due to difficulty of this task in cryptography, an external library was used.\n
    This library could be replaced by a bespoke function,
    but it would be very inefficient if written in Python.
    
    :param no_bits: Bit length of the prime factors used to construct the RSA modulus.
    :type no_bits: int
    :return: random prime.
    :rtype: int
    """
    assert no_bits >= 2

    return number.getPrime(no_bits)

def keygen(no_bits: int) -> tuple[int, int, int]:
    """
    Generates a private & public key of desired bit length, along with the RSA modulus,
    to be used in RSA encryption.
    
    :param no_bits: Bit length of private, public encryption key.
    :type no_bits: int
    :return: public key, private key, RSA modulus.
    :rtype: tuple[int, int, int]
    """
    # get 2 distinct primes
    p = random_prime(no_bits)
    q = random_prime(no_bits)
    while p == q:
        q = random_prime(no_bits)

    # modulus
    n = p * q

    # Eulers totient (for prime numbers)
    phi = (p - 1) * (q - 1)
    
    # public exponent
    e = 65537

    # safety
    if phi % e == 0:
        # NOTE add error handling here, do while?
        raise ValueError("Unlucky primes, keygen failed")
    
    # private exponent
    d = pow(e, -1, phi)

    return e, d, n

# CONVERTING THE DATA INTO BLOCKS
def validate_block_size(block_size: int, n: int):
    """
    An important function, validating that the blocks are not too big for RSA modulus.\n
    Throws a ValueError if the block size is too large.

    :param block_size: Size of blocks (in bytes).
    :type block_size: int
    :param n: RSA modulus.
    :type n: int
    """
    if block_size * 8 >= n.bit_length():
        raise ValueError("Block size too large for RSA modulus")

def pad_message(message: bytes, block_size: int) -> bytes:
    """
    Pads the message so that its length is a multiple of the block size.
    
    :param message: Message to be paded in byte form.
    :type message: bytes
    :param block_size: Desired block size for the padding.
    :type block_size: int
    :return: Paded message.
    :rtype: bytes
    """
    # PKCS-style padding
    # NOTE can fail if the padding exceeds 255 (one byte)
    padding_len = block_size - (len(message) % block_size)
    return message + bytes([padding_len] *  padding_len) # appends padding_len bytes, each equal to padding_len


def unpad_message(message: bytes) -> bytes:
    """
    Unpads the message.
    
    :param message: Message to be unpaded in byte form.
    :type message: bytes
    :return: Unpaded message.
    :rtype: bytes
    """
    padding_len = message[-1]
    return message[:-padding_len]

def string_to_blocks(text: str, block_size: int) -> list[int]:
    """
    Converts a string to a list of integers representing message blocks, ready for encryption.
    
    :param text: Text to be divided into blocks.
    :type text: str
    :param block_size: Desired size of blocks (bytes).
    :type block_size: int
    :return: Text converted to a list of integers "blocks".
    :rtype: list[int]
    """

    # pad the message
    # print(f"text is:\n{text}")
    message = text.encode("utf-8")
    # print(f"message encoded in utf-8 is:\n{message}")
    message = pad_message(message, block_size)
    # print(f"padded message (block size = {block_size}) is:\n{message}")

    # convert the message into blocks
    blocks = []
    for i in range(0, len(message), block_size):
        # iterate over the message
        block = message[i: i+block_size]
        block_int = int.from_bytes(block, byteorder="big")
        blocks.append(block_int)
    # print(f"message in block form is:\n{blocks}")
    return blocks

def blocks_to_string(blocks: list[int], block_size: int) -> str:
    """
    Converts a list of integers (blocks) back into a single string.
    
    :param blocks: Blocks to be converted.
    :type blocks: list[int]
    :param block_size: Size of blocks.
    :type block_size: int
    :return: Converted text.
    :rtype: str
    """
    message = b""
    for block in blocks:
        chunk = block.to_bytes(block_size, byteorder="big")
        message += chunk

    message = unpad_message(message)
    # print(f"decoded message is:\n {message}")
    return message.decode("utf-8")

# Wiktor add your documentation here

def rsa_encrypt_block(m: int, e: int, n: int) -> int:
    """
    Docstring for rsa_encrypt_block
    
    :param m: Description
    :type m: int
    :param e: Description
    :type e: int
    :param n: Description
    :type n: int
    :return: Description
    :rtype: int
    """
    if m >= n:
        raise ValueError("Block too large for modulus")
    return pow(m, e, n)

def rsa_decrypt_block(c: int, d: int, n: int) -> int:
    """
    Docstring for rsa_decrypt_block
    
    :param c: Description
    :type c: int
    :param d: Description
    :type d: int
    :param n: Description
    :type n: int
    :return: Description
    :rtype: int
    """
    return pow(c, d, n)