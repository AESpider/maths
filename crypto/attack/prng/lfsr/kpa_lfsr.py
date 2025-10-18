#!/usr/bin/env python3
"""
LFSR Stream Cipher - PNG Known Plaintext Attack

Usage:
    python3 kpa_lfsr.py image.png.enc

It will output `image.png` decrypted.
"""

import sys
from pathlib import Path

# --------  Helpers  --------
def bytes_to_bits(b: bytes):
    """Convert bytes to list of bits (MSB first within each byte)."""
    bits = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits

def bits_to_byte(bits):
    """Convert 8 bits (MSB first) to a single byte integer."""
    v = 0
    for bit in bits:
        v = (v << 1) | (bit & 1)
    return v

def berlekamp_massey(s):
    """
    s: list of bits (0/1)
    returns: (C, L) where C[0..L] is feedback poly (C[0]=1), L is degree.
    The recurrence: for n >= L, s[n] = sum_{i=1..L} C[i] * s[n-i]
    """
    n = len(s)
    C = [1] + [0]*n
    B = [1] + [0]*n
    L = 0
    m = 1
    for N in range(n):
        # compute discrepancy
        d = 0
        for i in range(L+1):
            d ^= (C[i] & s[N-i])
        if d == 1:
            T = C[:]
            # C = C + x^m * B
            for i in range(n - m + 1):
                C[m + i] ^= B[i]
            if 2*L <= N:
                B = T
                m = 1
                L = N + 1 - L
            else:
                m += 1
        else:
            m += 1
    # trim C to degree L
    return C[:L+1], L


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 kpa_lfsr.py <file.enc>")
        return

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print("File not found:", input_path)
        return
    
    # Known plaintext: PNG signature (8 bytes) + IHDR length (4 bytes) + 'IHDR' (4 bytes)
    # signature: 0x89 50 4E 47 0D 0A 1A 0A
    # IHDR length: 0x00 00 00 0D
    # chunk type: 'IHDR' = 0x49 48 44 52
    known_plaintext = (
        b"\x89PNG\r\n\x1a\n" +
        b"\x00\x00\x00\x0d" +
        b"IHDR"
    )
    known_size = len(known_plaintext) # 16 bytes

    data = input_path.read_bytes()
    if len(data) < known_size:
        print("Ciphertext too short")
        return

    # Extract first 16 bytes and produce keystream bits
    ciphertext_bits = bytes_to_bits(data[:known_size])
    plaintext_bits = bytes_to_bits(known_plaintext)
    keystream_known = [ (ciphertext_bits[i] ^ plaintext_bits[i]) for i in range(len(plaintext_bits)) ] 
    total_known_bits = len(keystream_known) # 128 bits

    C, L = berlekamp_massey(keystream_known)
    print(f"Berlekamp-Massey: L_found = {L}")

    taps = [i for i in range(1, L + 1) if C[i] == 1]
    initial_state = keystream_known[:L]

    print("Discovered taps (1-indexed):", taps)
    print("Initial state (64 bits):", "".join(str(x) for x in initial_state))

   # Verify first known bits
    gen = initial_state[:]
    for i in range(L, total_known_bits):
        new_bit = 0
        for t in taps:
            new_bit ^= gen[i - t]
        gen.append(new_bit)

    print(f"Match on first {total_known_bits} bits:", gen[:total_known_bits] == keystream_known)

    # Generate full keystream
    total_bits = len(data) * 8
    for i in range(total_known_bits, total_bits):
        new_bit = 0
        for t in taps:
            new_bit ^= gen[i - t]
        gen.append(new_bit)

    # Decrypt
    decrypted = bytearray()
    for byte_index in range(len(data)):
        kbits = gen[byte_index*8 : byte_index*8 + 8]
        k = bits_to_byte(kbits)
        decrypted.append(data[byte_index] ^ k)

    if decrypted.startswith(known_plaintext):
        output_path = input_path.with_suffix("")  # remove .enc
        output_path.write_bytes(decrypted)
        print("Decrypted file written to:", output_path)
    else:
        print("Warning: decrypted file does not start with PNG header.")

if __name__ == "__main__":
    main()
