#!/usr/bin/env python3
"""
AES-128 CBC IV Recovery.

Recovering the Initialization Vector (IV) from AES-CBC encrypted 
messages when the key and partial plaintext are known.

Principle:
  - In CBC mode: plaintext = AES_decrypt(ciphertext) ⊕ IV
  - Rearranging: IV = AES_decrypt(ciphertext) ⊕ plaintext
  - Decrypts first block using ECB mode
  - XORs result with known plaintext to recover IV

Usage: python3 iv_recovery.py
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, binascii

if __name__ == '__main__':
    print("AES-128 CBC IV Recovery\n")

    # Generate a random AES-128 key and IV
    key = os.urandom(16)
    iv = os.urandom(16) # random 16-byte IV

    # need just first 16 bytes of the message
    plaintext = "f4k3_f0r_t3st1ng"    
    aes_cbc = AES.new(key, AES.MODE_CBC, iv)

    # encrypt the plaintext (CBC + PKCS#7)
    ciphertext = aes_cbc.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))

    # show generated values
    print("Generated key:", binascii.hexlify(key).decode())
    print("Generated IV :", binascii.hexlify(iv).decode())
    print("Ciphertext:", binascii.hexlify(ciphertext).decode())

    # Extract first ciphertext block (16 bytes for AES-128)
    first_block = ciphertext[:16]

    # Decrypt first block using ECB mode
    aes_ecb = AES.new(key, AES.MODE_ECB)
    decrypted_block = aes_ecb.decrypt(first_block)

    # Recover IV by XORing decrypted block with known plaintext
    # In CBC mode: plaintext = decrypt(ciphertext) XOR IV
    # Therefore: IV = decrypt(ciphertext) XOR plaintext
    iv_recovered = bytes([decrypted_block[i] ^ ord(plaintext[i]) for i in range(16)])

    # Verify recovered IV
    print("\nRecovered IV:", iv_recovered.hex())
    print("Match ?", iv == iv_recovered)
