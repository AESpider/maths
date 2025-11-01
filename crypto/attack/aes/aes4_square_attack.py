#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Square (Integral) attack on 4-round AES-128 (final round without MixColumns).

Demonstrates the Square attack against 4-round AES-128 where the final round omits MixColumns. 
The attack uses chosen-plaintext structures: one active byte cycles through all 256 possible 
values while the other bytes remain constant. By exploiting the integral (balanced) property, 
the attacker can recover the last-round key. The master key is then reconstructed by 
inverting the AES key schedule.

Usage: python3 aes4_square_attack.py
"""

import random
from typing import List, Tuple

# AES S-box and Inverse S-box
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i


# State Representation (Column-major order)
def bytes_to_state(data: bytes) -> List[List[int]]:
    """Convert 16-byte block to 4x4 state matrix (column-major)."""
    assert len(data) == 16
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        col = i // 4
        row = i % 4
        state[col][row] = data[i]
    return state


def state_to_bytes(state: List[List[int]]) -> bytes:
    """Convert 4x4 state matrix back to 16-byte block."""
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[col][row] & 0xFF)
    return bytes(result)


# AES Round Operations
def sub_bytes(state: List[List[int]]) -> None:
    """Apply S-box substitution to each byte in state."""
    for col in range(4):
        for row in range(4):
            state[col][row] = SBOX[state[col][row]]


def shift_rows(state: List[List[int]]) -> None:
    """Shift rows: row i shifted left by i positions."""
    rows = [[state[c][r] for c in range(4)] for r in range(4)]
    for r in range(4):
        rows[r] = rows[r][r:] + rows[r][:r]
    for col in range(4):
        for row in range(4):
            state[col][row] = rows[row][col]


def galois_multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with AES irreducible polynomial."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B  # AES irreducible polynomial
        b >>= 1
    return result & 0xFF


def mix_column(col: List[int]) -> None:
    """Apply MixColumns transformation to a single column."""
    temp = col[:]
    col[0] = galois_multiply(temp[0], 2) ^ galois_multiply(temp[1], 3) ^ temp[2] ^ temp[3]
    col[1] = temp[0] ^ galois_multiply(temp[1], 2) ^ galois_multiply(temp[2], 3) ^ temp[3]
    col[2] = temp[0] ^ temp[1] ^ galois_multiply(temp[2], 2) ^ galois_multiply(temp[3], 3)
    col[3] = galois_multiply(temp[0], 3) ^ temp[1] ^ temp[2] ^ galois_multiply(temp[3], 2)


def mix_columns(state: List[List[int]]) -> None:
    """Apply MixColumns to all columns in state."""
    for col in range(4):
        mix_column(state[col])


def add_round_key(state: List[List[int]], round_key: bytes) -> None:
    """XOR state with round key."""
    key_state = bytes_to_state(round_key)
    for col in range(4):
        for row in range(4):
            state[col][row] ^= key_state[col][row]


# AES-128 Key Schedule
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def expand_key(master_key: bytes) -> List[bytes]:
    """Generate 11 round keys from 128-bit master key."""
    assert len(master_key) == 16
    
    key_bytes = list(master_key)
    rcon_index = 1
    
    # Expand to 176 bytes (11 round keys * 16 bytes)
    while len(key_bytes) < 176:
        # Take last 4 bytes
        temp = key_bytes[-4:]
        
        # Every 16 bytes: apply RotWord, SubWord, and XOR with Rcon
        if len(key_bytes) % 16 == 0:
            temp = temp[1:] + temp[:1]      # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[rcon_index]
            rcon_index += 1
        
        # XOR with bytes from 16 positions back
        for i in range(4):
            key_bytes.append(key_bytes[-16] ^ temp[i])
    
    # Split into 11 round keys
    return [bytes(key_bytes[16*i:16*(i+1)]) for i in range(11)]


# AES Encryption (Reduced Rounds)
def aes_encrypt(plaintext: bytes, round_keys: List[bytes], num_rounds: int = 4) -> bytes:
    """
    Encrypt a single block using reduced-round AES.
    Last round omits MixColumns operation.
    """
    assert len(plaintext) == 16
    
    state = bytes_to_state(plaintext)
    add_round_key(state, round_keys[0])
    
    # Full rounds (with MixColumns)
    for round_num in range(1, num_rounds):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_num])
    
    # Final round (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[num_rounds])
    
    return state_to_bytes(state)


# Key Recovery from Round Key
def recover_master_key(round_key: bytes, round_index: int) -> bytes:
    """
    Reverse the key schedule to recover master key from a known round key.
    Works for AES-128 by undoing the key expansion process.
    """
    assert len(round_key) == 16
    
    # Convert to 4-word representation
    words = [[round_key[4*i + j] for j in range(4)] for i in range(4)]
    
    # Backtrack through key schedule
    for r in range(round_index, 0, -1):
        w0, w1, w2, w3 = words
        
        # Reverse key schedule equations:
        # w3_prev = w3 ^ w2
        # w2_prev = w2 ^ w1
        # w1_prev = w1 ^ w0
        # w0_prev = w0 ^ SubWord(RotWord(w3_prev)) ^ Rcon[r]
        
        w3_prev = [w3[i] ^ w2[i] for i in range(4)]
        w2_prev = [w2[i] ^ w1[i] for i in range(4)]
        w1_prev = [w1[i] ^ w0[i] for i in range(4)]
        
        temp = w3_prev[1:] + w3_prev[:1]   # RotWord
        temp = [SBOX[b] for b in temp]     # SubWord
        temp[0] ^= RCON[r]
        
        w0_prev = [(w0[i] ^ temp[i]) & 0xFF for i in range(4)]
        words = [w0_prev, w1_prev, w2_prev, w3_prev]
    
    # Flatten words back to bytes
    return bytes([b for word in words for b in word])


# Square Attack Implementation
def generate_structure(active_byte_index: int) -> List[bytes]:
    """
    Generate a plaintext structure where one byte takes all 256 values
    and all other bytes are constant (set to 0).
    """
    structure = []
    base = bytearray(16)
    
    for value in range(256):
        plaintext = base[:]
        plaintext[active_byte_index] = value
        structure.append(bytes(plaintext))
    
    return structure


def analyze_structure(encrypt_oracle, active_byte_index: int) -> List[List[int]]:
    """
    Perform square attack on one structure.
    Returns list of candidate key bytes for each ciphertext position.
    """
    # Generate and encrypt structure
    plaintexts = generate_structure(active_byte_index)
    ciphertexts = [encrypt_oracle(pt) for pt in plaintexts]
    
    candidates = [[] for _ in range(16)]
    
    # For each byte position in ciphertext
    for byte_pos in range(16):
        # Try all possible key byte values
        for key_guess in range(256):
            # Check if XOR of inverse S-box outputs equals zero (balanced property)
            xor_sum = 0
            for ct in ciphertexts:
                partial_decrypt = INV_SBOX[ct[byte_pos] ^ key_guess]
                xor_sum ^= partial_decrypt
            
            # If balanced, this key guess is a candidate
            if xor_sum == 0:
                candidates[byte_pos].append(key_guess)
    
    return candidates


def square_attack(encrypt_oracle, active_indices: Tuple[int, ...] = (0, 1, 2, 3)) -> bytes:
    """
    Perform square attack using multiple structures and intersect candidates.
    Returns the recovered last-round key.
    """
    all_structure_candidates = []
    
    # Analyze each structure
    for idx in active_indices:
        candidates = analyze_structure(encrypt_oracle, idx)
        all_structure_candidates.append(candidates)
    
    # Intersect candidates across structures for each byte position
    final_candidates = []
    for byte_pos in range(16):
        candidate_sets = [set(struct[byte_pos]) for struct in all_structure_candidates]
        intersection = set.intersection(*candidate_sets)
        final_candidates.append(sorted(intersection))
    
    return all_structure_candidates, final_candidates


if __name__ == "__main__":
    print("Square attack on 4-round AES-128 (final round without MixColumns)\n")
    # Generate random 128-bit key
    master_key = bytes([random.randint(0, 255) for _ in range(16)])
    round_keys = expand_key(master_key)
    print(f"Target master key: {master_key.hex()}")
    
    # Create encryption oracle
    def encryption_oracle(plaintext: bytes) -> bytes:
        return aes_encrypt(plaintext, round_keys, num_rounds=4)
    
    # Perform attack
    print("\nPerforming square attack with 4 structures...")
    structure_results, final_candidates = square_attack(encryption_oracle)
    
    # Display results
    print(f"\nCandidates per byte: {[len(c) for c in final_candidates]}")
    
    # Check if attack succeeded
    if all(len(candidates) == 1 for candidates in final_candidates):
        recovered_round_key = bytes(candidates[0] for candidates in final_candidates)
        recovered_master_key = recover_master_key(recovered_round_key, round_index=4)
        
        print(f"\nAttack successful!")
        print(f"  Last-round key:  {recovered_round_key.hex()}")
        print(f"  Recovered key:   {recovered_master_key.hex()}")
        print(f"  Match ? {recovered_master_key == master_key}")
    else:
        print("\nAttack failed..")
        print("Candidates by position:")
        for i, candidates in enumerate(final_candidates):
            print(f"  Byte {i:2d}: {candidates}")