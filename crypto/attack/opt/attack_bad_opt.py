#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attack on Flawed OTP Implementation.

Demonstrates a attack against an OTP encryption service that:
  1. Generates a fresh random OTP for each encryption
  2. Filters out 0x00 bytes from the OTP
  3. Encrypts the same plaintext multiple times

The attack uses process of elimination to recover the plaintext by observing
which ciphertext bytes never appear at each position across many encryptions.

Usage: python3 attack_bad_opt.py
"""

import os
from collections import defaultdict
from typing import Set

FLAG = b"FLAG{f4k3_f0r_t3st1ng}" 

# Vulnerable OTP Implementation
def generate_otp(length: int) -> bytes:
    """
    Generate One-Time Pad with a critical flaw:
    Filters out 0x00 bytes, reducing effective keyspace from 256 to 255 values.
    """
    key = []
    for _ in range(length):
        byte = os.urandom(1)[0]
        
        # VULNERABILITY: Regenerate if byte is 0x00
        # This means certain ciphertext values can never appear
        while byte <= 0x00 or byte > 0xff:
            byte = os.urandom(1)[0]
        
        key.append(byte)
    
    return bytes(key)


def otp_encrypt(plaintext: bytes, otp: bytes) -> bytes:
    """XOR plaintext with OTP key."""
    return bytes([otp[i] ^ plaintext[i] for i in range(len(plaintext))])


def get_encrypted_flag() -> bytes:
    """
    Simulate encryption oracle that generates fresh OTP each time.
    This a vulnerable service that encrypts the same flag repeatedly.
    """
    return otp_encrypt(FLAG, generate_otp(len(FLAG)))

# Attack Implementation
def recover_flag_by_elimination(printable_range: Set[int] = None) -> tuple[bytes, int]:
    """
    Recover plaintext through elimination attack. 

    printable_range: Set of expected plaintext byte values (default: ASCII 32-126)
    
    The attack works because:
      1. OTP never contains 0x00, so some ciphertext values are impossible
      2. For each position i: ciphertext[i] = plaintext[i] ^ otp[i]
      3. If plaintext[i] is known to be printable ASCII, we can deduce it
          by elimination when we've seen all impossible ciphertext values
    
    Returns: Tuple of (recovered_plaintext, number_of_rounds_needed)
    """
    if printable_range is None:
        # Assume printable ASCII characters
        printable_range = set(range(32, 127))
    
    # Track which ciphertext bytes we've observed at each position
    observed_ciphertexts = defaultdict(set)
    
    # Track recovered plaintext bytes
    recovered_bytes = [None] * len(FLAG)
    
    rounds = 0
    while True:
        rounds += 1
        
        # Get a new ciphertext sample
        ciphertext = get_encrypted_flag()
        
        # Record observed ciphertext bytes
        for position, byte_value in enumerate(ciphertext):
            observed_ciphertexts[position].add(byte_value)
        
        # Try to recover each position
        all_recovered = True
        
        for position in range(len(FLAG)):
            if recovered_bytes[position] is not None:
                continue  # Already recovered
            
            # Candidate plaintexts are those in printable_range and we haven't ruled out yet
            # For each observed ciphertext C, we eliminate plaintext P where C = P ^ 0
            # Since 0x00 never appears in OTP, we eliminate P where C = P ^ (any seen byte)
            
            impossible_plaintexts = observed_ciphertexts[position]
            possible_plaintexts = printable_range - impossible_plaintexts
            
            if len(possible_plaintexts) == 1:
                # Only one candidate remains - we've recovered this byte!
                recovered_bytes[position] = possible_plaintexts.pop()
            else:
                all_recovered = False
        
        if all_recovered:
            break
    
    recovered_flag = bytes(recovered_bytes)
    return recovered_flag, rounds

# Run the elimination attack.
if __name__ == "__main__":
    print("Launching attack on bad OTP - Process of Elimination\n")
    print(f"[+] Flag length: {len(FLAG)} bytes")
    
    # For a printable ASCII byte P and non-zero OTP byte K:
    #     - Ciphertext C = P ^ K can take 255 different values (K in [1,255])
    #     - The one impossible value is C = P ^ 0 = P
    #     - After seeing enough samples, the only unseen value reveals P
      
    recovered_flag, rounds_needed = recover_flag_by_elimination()
    
    print(f"\n[+] Attack successful!")
    print(f"    Rounds needed: {rounds_needed} ({rounds_needed / len(FLAG):.1f} rounds/byte)")
    print(f"    Recovered flag: {recovered_flag.decode('utf-8')}")
    print(f"    Match ? {recovered_flag == FLAG}")
