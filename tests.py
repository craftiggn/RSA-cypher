import rsa_core
import ecb  
import cbc
import unittest


#Fixed test keys for reference value testing
REF_P = 61
REF_Q = 53
REF_N = REF_P * REF_Q  # 3233
REF_E = 17
REF_D = 2753  # pow(17, -1, 3120) = 2753

#Reference test vectors: (plaintext_int, expected_ciphertext_int)
#Computed using: pow(m, e, n) where e=17, n=3233
#can be independently verified using any RSA implementation or calculator
REFERENCE_TEST_VECTORS = [
    (65, 2790),      # 'A' -> pow(65, 17, 3233) = 2790
    (66, 524),       # 'B' -> pow(66, 17, 3233) = 524
    (72, 3000),      # 'H' -> pow(72, 17, 3233) = 3000
    (89, 99),        # 'Y' -> pow(89, 17, 3233) = 99
    (123, 855),      # '{' -> pow(123, 17, 3233) = 855
    (1000, 175),     # 1000 -> pow(1000, 17, 3233) = 175
    (2000, 2698),    # 2000 -> pow(2000, 17, 3233) = 2698
]


class TestRSAReferenceValues(unittest.TestCase):
    """
    Test class using externally verifiable reference values.
    
    These tests compare the RSA implementation output against known reference
    values computed using Python's trusted pow() function for modular exponentiation.
    The reference values can be independently verified using:
    - Python: pow(m, e, n)
    - Linux: openssl or any RSA calculator
    - Manual calculation: m^e mod n
    """
    
    def test_reference_encryption_vector_1(self):
        """Test encryption of 'A' (65) with reference RSA parameters."""
        m, expected_c = 65, 2790  # pow(65, 17, 3233) = 2790
        actual_c = rsa_core.rsa_encrypt_block(m, REF_E, REF_N)
        self.assertEqual(actual_c, expected_c, 
            f"Encryption of {m} should be {expected_c}, got {actual_c}")
    
    def test_reference_encryption_vector_2(self):
        """Test encryption of 'B' (66) with reference RSA parameters."""
        m, expected_c = 66, 524  # pow(66, 17, 3233) = 524
        actual_c = rsa_core.rsa_encrypt_block(m, REF_E, REF_N)
        self.assertEqual(actual_c, expected_c,
            f"Encryption of {m} should be {expected_c}, got {actual_c}")
    
    def test_reference_encryption_vector_3(self):
        """Test encryption of 'H' (72) with reference RSA parameters."""
        m, expected_c = 72, 3000  # pow(72, 17, 3233) = 3000
        actual_c = rsa_core.rsa_encrypt_block(m, REF_E, REF_N)
        self.assertEqual(actual_c, expected_c,
            f"Encryption of {m} should be {expected_c}, got {actual_c}")
    
    def test_reference_decryption_vector_1(self):
        """Test decryption of ciphertext 2790 back to 'A' (65)."""
        c, expected_m = 2790, 65  # pow(2790, 2753, 3233) = 65
        actual_m = rsa_core.rsa_decrypt_block(c, REF_D, REF_N)
        self.assertEqual(actual_m, expected_m,
            f"Decryption of {c} should be {expected_m}, got {actual_m}")
    
    def test_reference_decryption_vector_2(self):
        """Test decryption of ciphertext 524 back to 'B' (66)."""
        c, expected_m = 524, 66  # pow(524, 2753, 3233) = 66
        actual_m = rsa_core.rsa_decrypt_block(c, REF_D, REF_N)
        self.assertEqual(actual_m, expected_m,
            f"Decryption of {c} should be {expected_m}, got {actual_m}")
    
    def test_reference_encrypt_decrypt_roundtrip(self):
        """Test full encrypt-decrypt cycle against reference values."""
        for m, expected_c in REFERENCE_TEST_VECTORS:
            with self.subTest(plaintext=m):
                # Encrypt and verify against reference
                actual_c = rsa_core.rsa_encrypt_block(m, REF_E, REF_N)
                self.assertEqual(actual_c, expected_c,
                    f"Encryption of {m}: expected {expected_c}, got {actual_c}")
                
                # Decrypt and verify roundtrip
                decrypted = rsa_core.rsa_decrypt_block(actual_c, REF_D, REF_N)
                self.assertEqual(decrypted, m,
                    f"Decryption of {actual_c}: expected {m}, got {decrypted}")
    
    def test_reference_larger_message(self):
        """Test with larger message value (1000) using reference values."""
        m, expected_c = 1000, 175  # pow(1000, 17, 3233) = 175
        actual_c = rsa_core.rsa_encrypt_block(m, REF_E, REF_N)
        self.assertEqual(actual_c, expected_c,
            f"Encryption of {m} should be {expected_c}, got {actual_c}")
        
        #Verify decryption
        actual_m = rsa_core.rsa_decrypt_block(expected_c, REF_D, REF_N)
        self.assertEqual(actual_m, m,
            f"Decryption of {expected_c} should be {m}, got {actual_m}")






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