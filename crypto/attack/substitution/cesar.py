#!/usr/bin/env python3
"""Caesar brute-force: try all possible shifts (1-25)."""

def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt text with a given Caesar shift."""
    result = []
    for ch in text:
        if ch.isalpha():
            # choose base depending on case
            base = ord('A') if ch.isupper() else ord('a')
            # apply shift while preserving case
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            # keep non-alphabetic characters unchanged
            result.append(ch)
    return ''.join(result)

def bruteforce_caesar(ciphertext: str) -> None:
    """Print all possible decryptions."""
    print(f"Ciphertext: {ciphertext}\n")
    for shift in range(1, 26):
        print(f"Shift {shift}: {caesar_decrypt(ciphertext, shift)}")

if __name__ == "__main__":
    ciphertext = "AVFZ AGVB AJM OZNODIB"
    bruteforce_caesar(ciphertext)
