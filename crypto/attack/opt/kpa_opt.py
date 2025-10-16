#!/usr/bin/env python3
import base64

def byte_xor(a: bytes, b: bytes) -> bytes:
    """XOR between two byte sequences (stops at shortest)."""
    return bytes([x ^ y for x, y in zip(a, b)])

def known_plaintext_attack(ciphertext_b64: str, plaintext: str) -> str:
    """Perform a known-plaintext attack to recover the XOR keystream."""
    ciphertext = base64.b64decode(ciphertext_b64)
    pt_bytes = plaintext.encode()
    key_bytes = byte_xor(ciphertext, pt_bytes)
    return key_bytes.decode(errors='replace')

if __name__ == "__main__":
    # EDIT ME: Replace with your base64-encoded ciphertext and plaintext
    ciphertext_b64 = "EikyM1sLURhAPgEKUjkbQVMsfjxGXA=="
    plaintext = "Test message for XOR!!"

    key = known_plaintext_attack(ciphertext_b64, plaintext)
    print("Recovered key:", key)
