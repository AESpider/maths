#!/usr/bin/env python3
"""
SHA-256 length-extension attack.

Demonstrates a length-extension attack against a naive MAC = SHA256(secret || payload). 
The attacker, given (payload, MAC), forges a new payload' = payload || glue || suffix and
computes a valid MAC for payload' without knowing the secret, by continuing the SHA-256 
compression from the observed internal state.

Goal: Change "role=guest" -> "role=admin" by appending "&role=admin" to the payload,
relying on parsers that accept the last occurrence of a repeated parameter.

Usage: python3 length-extension_attack.py
"""

import os
import struct
import hashlib
import random

# SHA-256 helpers 
K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]

def _rotr(x, n):
    return ((x >> n) | ((x & 0xFFFFFFFF) << (32 - n))) & 0xFFFFFFFF

# Compress a single 64-byte block with state H (8 words)
def _sha256_compress_block(block, H):
    w = list(struct.unpack('>16I', block))
    for t in range(16, 64):
        s0 = (_rotr(w[t-15], 7) ^ _rotr(w[t-15], 18) ^ (w[t-15] >> 3)) & 0xFFFFFFFF
        s1 = (_rotr(w[t-2], 17) ^ _rotr(w[t-2], 19) ^ (w[t-2] >> 10)) & 0xFFFFFFFF
        w.append((w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFF)
    a,b,c,d,e,f,g,h = H
    for t in range(64):
        S1 = (_rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)) & 0xFFFFFFFF
        ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFF
        temp1 = (h + S1 + ch + K[t] + w[t]) & 0xFFFFFFFF
        S0 = (_rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)) & 0xFFFFFFFF
        maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
        temp2 = (S0 + maj) & 0xFFFFFFFF
        h = g; g = f; f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c; c = b; b = a
        a = (temp1 + temp2) & 0xFFFFFFFF
    return [
        (H[0] + a) & 0xFFFFFFFF,
        (H[1] + b) & 0xFFFFFFFF,
        (H[2] + c) & 0xFFFFFFFF,
        (H[3] + d) & 0xFFFFFFFF,
        (H[4] + e) & 0xFFFFFFFF,
        (H[5] + f) & 0xFFFFFFFF,
        (H[6] + g) & 0xFFFFFFFF,
        (H[7] + h) & 0xFFFFFFFF,
    ]

# Standard SHA-256 padding for message of given byte length
def sha256_padding_for_length(message_len_bytes):
    ml_bits = message_len_bytes * 8
    pad = b'\x80'
    zeros_len = (56 - (message_len_bytes + 1) % 64) % 64
    pad += b'\x00' * zeros_len
    pad += struct.pack('>Q', ml_bits)
    return pad

# Continue SHA-256 from internal state 
# H_initial as if previous_message_len bytes were already processed
def sha256_from_state(msg_bytes, H_initial, previous_message_len):
    H = list(H_initial)
    total_len = previous_message_len + len(msg_bytes)
    padding = sha256_padding_for_length(total_len)
    to_process = msg_bytes + padding
    i = 0
    while i < len(to_process):
        block = to_process[i:i+64]
        if len(block) < 64:
            block = block.ljust(64, b'\x00')
        H = _sha256_compress_block(block, H)
        i += 64
    return ''.join('{:08x}'.format(x) for x in H)

# server computes a simple SHA-256(secret || payload)
def server_mac(secret: bytes, payload: bytes) -> str:
    return hashlib.sha256(secret + payload).hexdigest()

# forging function build glue padding for (key || orig_payload)
def forge_length_extension(orig_payload: bytes, orig_mac_hex: str, guessed_key_len: int, suffix: bytes):
    total_prev = guessed_key_len + len(orig_payload)
    glue = sha256_padding_for_length(total_prev)
    prev_len = total_prev + len(glue)
    # parse original mac into 8 words (internal state)
    h_words = [int(orig_mac_hex[i:i+8], 16) for i in range(0, len(orig_mac_hex), 8)]
    # compute forged mac as continuation
    forged_mac = sha256_from_state(suffix, h_words, prev_len)
    forged_payload = orig_payload + glue + suffix
    return forged_payload, forged_mac

if __name__ == '__main__':
    print("SHA-256 length-extension attack\n")

    # Generate secret 
    secret_len = random.randint(8, 24)
    secret = os.urandom(secret_len)

    # Payload and MAC
    orig_payload = b"user=alice&role=guest"
    orig_mac = server_mac(secret, orig_payload)

    print("Generated secret length:", secret_len)
    print("Original payload:", orig_payload)
    print("Mac:", orig_mac)

    # We wants to append a new role 
    # many naive parsers just accept last parameter
    suffix = b"&role=admin"

    # Tries plausible key lengths
    found = False
    for guessed in range(1, 48):
        forged_payload, forged_mac = forge_length_extension(orig_payload, orig_mac, guessed, suffix)
        
        # Verifies
        true_mac = server_mac(secret, forged_payload)
        if true_mac == forged_mac:
            print("\nSuccess! guessed key len:", guessed)
            print("Forged payload:", forged_payload[:200])
            print("Mac:", forged_mac)
            found = True
    
    if not found:
        print("Failed to forge in tested range (1..47)")
