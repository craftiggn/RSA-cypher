import rsa_core 
import ecb 
import cbc


# testing for the complete CBC encryption
if True:
    text = "Bicycle Day is an unofficial celebration on April 19th of the psychedelic revolution[1] and the first psychedelic trip on LSD by Albert Hofmann in 1943, in tandem with his bicycle ride home from Sandoz Labs.[2][3] It is commonly celebrated by ingesting psychedelics and riding a bike, sometimes in a parade,[4] and often with psychedelic-themed festivities.[5] The holiday was first named and declared in 1985 by Thomas Roberts, a psychology professor at Northern Illinois University,[6][7] but has likely been celebrated by psychedelic enthusiasts since the beginning of the psychedelic era, and celebrated in popular culture since at least 2004.[8]"

    public_key, private_key, modulus = rsa_core.keygen(64)
    block_size = 8
    rsa_core.validate_block_size(block_size, modulus) # important! 

    initialisation_vector, encrypted_content = cbc.encrypt_text(text, public_key, modulus, block_size)
    print(f"initialisation_vector:\n{initialisation_vector}")
    print(f"encrypted text:\n{encrypted_content}")

    decrypted_text = cbc.decrypt_text(encrypted_content, private_key, modulus, initialisation_vector, block_size)
    print(f"the text is decrypted back to:\n{decrypted_text}")