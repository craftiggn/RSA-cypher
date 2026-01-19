"""
- make the encryption work on binary/hexadecimal representation of the data,
such that any data type can be segmented and subbmitted to the algorithm
- prioritize using numpy, wherever possible
- make sure to use prime, large numbers for key generation
- "ciphering blocks"
- what is the initialisation vector? it is public
- XOR
"""

# KEYGEN
from Crypto.Util import number
import random

def random_prime(no_bits: int) -> int:
    """
    Docstring for random_prime
    
    :param no_bits: Bit length of the desired prime.
    :type no_bits: int
    :return: random prime.
    :rtype: int
    """
    assert no_bits >= 2

    return number.getPrime(no_bits)

def is_prime(prime: int) -> bool:
    return True

def keygen(no_bits: int) -> tuple[int, int, int]:
    """
    Docstring for keygen
    
    :param no_bits: Description
    :type no_bits: int
    :return: Description
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


## CONVERTING THE DATA INTO BLOCKS

def generate_iv(block_size: int) -> int:
    min_val = 0
    max_val = 2 ** (block_size * 8) - 1
    return random.randint(min_val, max_val)

def pad_message(message: bytes, block_size: int) -> bytes:
    # PKCS-style padding
    # NOTE can fail if the padding exceeds 255 (one byte)
    padding_len = block_size - (len(message) % block_size)
    return message + bytes([padding_len] *  padding_len) # adds n number n numbers at the end of the message 

def unpad_message(message: bytes) -> bytes:
    padding_len = message[-1]
    return message[:-padding_len]

def convert_msg_to_blocks(message: bytes, block_size: int) -> list[int]:
    blocks = []
    # pad the message
    message = pad_message(message, block_size)

    # split the message into blocks
    for i in range(0, len(message), block_size):
        # iterate over the message
        block = message[i: i+block_size]
        block_int = int.from_bytes(block, byteorder="big")
        blocks.append(block_int)
    
    return blocks

def string_to_blocks(text: str, block_size: int) -> list[int]:

    # pad the message
    print(f"text is:\n{text}")
    message = text.encode("utf-8")
    print(f"message encoded in utf-8 is:\n{message}")
    message = pad_message(message, block_size)
    print(f"padded message (block size = {block_size}) is:\n{message}")

    # convert the message into blocks
    blocks = []
    for i in range(0, len(message), block_size):
        # iterate over the message
        block = message[i: i+block_size]
        block_int = int.from_bytes(block, byteorder="big")
        blocks.append(block_int)
    print(f"message in block form is:\n{blocks}")
    return blocks

def blocks_to_string(blocks: list[int], block_size: int) -> str:

    message = b""
    for block in blocks:
        chunk = block.to_bytes(block_size, byteorder="big")
        message += chunk

    message = unpad_message(message)
    print(f"decoded message is:\n {message}")
    return message.decode("utf-8")

# testing of the padding functionality
if True:
    text = "Bicycle Day is an unofficial celebration on April 19th of the psychedelic revolution[1] and the first psychedelic trip on LSD by Albert Hofmann in 1943, in tandem with his bicycle ride home from Sandoz Labs.[2][3] It is commonly celebrated by ingesting psychedelics and riding a bike, sometimes in a parade,[4] and often with psychedelic-themed festivities.[5] The holiday was first named and declared in 1985 by Thomas Roberts, a psychology professor at Northern Illinois University,[6][7] but has likely been celebrated by psychedelic enthusiasts since the beginning of the psychedelic era, and celebrated in popular culture since at least 2004.[8]"

    # text = "Bicycle Day (psychedelic holiday)"
    block_size = 10

    blocks = string_to_blocks(text, block_size)

    decoded_text = blocks_to_string(blocks, block_size)