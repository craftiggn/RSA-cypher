import rsa_core
import ecb  
import cbc
import unittest

class TestRSAModes(unittest.TestCase):
    def setUp(self):
        self.e, self.d, self.n = rsa_core.keygen(128)

        self.block_size = 16 

        rsa_core.validate_block_size(self.block_size, self.n)

    def test_ecb_basic(self):
        print("\n--- Testing ECB Mode ---")
        original_text = "Hello, this is a test of RSA ECB mode."
        
        # print(f"Original: {original_text}")
        
        encrypted_blocks = ecb.encrypt_text(original_text, self.e, self.n, self.block_size)
        # print(f"Encrypted blocks: {encrypted_blocks}")
        
        decrypted_text = ecb.decrypt_text(encrypted_blocks, self.d, self.n, self.block_size)
        # print(f"Decrypted: {decrypted_text}")
        
        self.assertEqual(original_text, decrypted_text)

    def test_ecb_patterns(self):
        print("\n--- Testing ECB Pattern Leakage ---")

        # ECB converts identical plaintext blocks into identical ciphertext blocks.
        block_a = "A" * self.block_size
        text = block_a + block_a
        
        encrypted_blocks = ecb.encrypt_text(text, self.e, self.n, self.block_size)
        
        print(f"Block 1: {encrypted_blocks[0]}")
        print(f"Block 2: {encrypted_blocks[1]}")
        
        self.assertEqual(encrypted_blocks[0], encrypted_blocks[1], "ECB should produce identical cipher blocks for identical plain blocks")

    def test_cbc_basic(self):
        print("\n--- Testing CBC Mode ---")
        original_text = "Bicycle Day is an unofficial celebration..."
        
        iv, encrypted_blocks = cbc.encrypt_text(original_text, self.e, self.n, self.block_size)
        decrypted_text = cbc.decrypt_text(encrypted_blocks, self.d, self.n, iv, self.block_size)
        
        self.assertEqual(original_text, decrypted_text)

    def test_cbc_iv_uniqueness(self):
        print("\n--- Testing CBC IV Randomness ---")
        text = "Same text, different encryption."
        
        # Encrypt twice
        iv1, enc1 = cbc.encrypt_text(text, self.e, self.n, self.block_size)
        iv2, enc2 = cbc.encrypt_text(text, self.e, self.n, self.block_size)
        
        self.assertNotEqual(iv1, iv2, "IVs should be random")
        self.assertNotEqual(enc1, enc2, "Ciphertext should differ due to different IVs")

    def test_padding_boundary(self):
        print("\n--- Testing Exact Block Size Padding ---")
        # Text length exactly matches block size
        text = "A" * self.block_size
        
        # ECB
        enc = ecb.encrypt_text(text, self.e, self.n, self.block_size)
        dec = ecb.decrypt_text(enc, self.d, self.n, self.block_size)
        self.assertEqual(text, dec)


    def test_block_size_validation(self):
        print("\n--- Testing Block Size Validation ---")
        # The modulus is 128 bits 
        # This means the integer value of the block could easily exceed n, causing data loss.

        too_large_block_size = 32
        
        print(f"Testing invalid block size: {too_large_block_size} (Modulus is ~16 bytes)")

        # Verify that the low-level validation function raises ValueError
        with self.assertRaises(ValueError):
            rsa_core.validate_block_size(too_large_block_size, self.n)

        # Verify that high-level functions also catch this error
        with self.assertRaises(ValueError):
            ecb.encrypt_text("This should fail", self.e, self.n, too_large_block_size)

if __name__ == '__main__':
    unittest.main()