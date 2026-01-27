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

    p = number.getPrime(no_bits)
    print(f"[KEYGEN] Generated prime ({no_bits} bits): {p}")
    return p

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

    print(f"[KEYGEN] p = {p}")
    print(f"[KEYGEN] q = {q}")

    # modulus
    n = p * q

    print(f"[KEYGEN] RSA modulus n = p*q = {n}")
    print(f"[KEYGEN] bit length of n = {n.bit_length()}")

    # Eulers totient (for prime numbers)
    phi = (p - 1) * (q - 1)
    
    # public exponent
    e = 65537

    print(f"[KEYGEN] Public exponent e = {e}")

    # safety
    if phi % e == 0:
        # NOTE add error handling here, do while?
        raise ValueError("Unlucky primes, keygen failed")
    
    # private exponent
    d = pow(e, -1, phi)

    print(f"[KEYGEN] Private exponent d = {d}")

    print("[KEYGEN] Key generation complete\n")
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
    print(f"[BLOCK CHECK] block_size = {block_size} bytes")
    print(f"[BLOCK CHECK] modulus bit length = {n.bit_length()} bits")

    if block_size * 8 >= n.bit_length():
        print(f"[BLOCK CHECK] block size invalid for RSA modulus")
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

    print(f"[PADDING] original length = {len(message)} bytes")
    print(f"[PADDING] padding length = {padding_len} bytes")

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
    print(f"[UNPADDING] detected padding length = {padding_len} bytes")
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
    print(f"[BLOCKING] original text:\n{text}")

    message = text.encode("utf-8")
    print(f"[BLOCKING] UTF-8 encoded bytes:\n{message}")

    message = pad_message(message, block_size)
    print(f"[BLOCKING] padded message:\n{message}")

    # convert the message into blocks
    blocks = []
    for i in range(0, len(message), block_size):
        # iterate over the message
        block = message[i: i+block_size]
        block_int = int.from_bytes(block, byteorder="big")
        blocks.append(block_int)

    print(f"[BLOCKING] all message blocks:\n{blocks}\n")
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
    print(f"[UNBLOCKING] unpadded message bytes:\n{message}")

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
    r =  pow(m, e, n)
    print(f"[ENCRYPT] plaintext block m = {m}")
    print(f"[ENCRYPT] ciphertext c = m^e mod n = {r}")
    return r


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
    r = pow(c, d, n)
    print(f"[DECRYPT] ciphertext block c = {c}")
    print(f"[DECRYPT] recovered plaintext m = c^d mod n = {pow(c, d, n)}")
    return r