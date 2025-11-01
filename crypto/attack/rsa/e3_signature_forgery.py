#!/usr/bin/env python3
"""
RSA e=3 PKCS#1 v1.5 forgery

This script demonstrates how a permissive PKCS#1 v1.5 verifier combined with a
small public exponent (e = 3) allows signature forgery to produce s such that 
s^3 [mod n] begins with the expected PKCS#1 prefix.

Principle:
  1. build a short PKCS#1 v1.5 block:
       0x00 || 0x01 || PS (few 0xFF bytes) || 0x00 || ASN1(SHA-256) || H
  2. left-align that prefix in a key-sized block (so it occupies the most
      significant bytes of the modulus-sized integer)
  3. compute the integer cube root (ceil) to obtain a candidate signature s
  4. optionally search a small neighborhood around s for a value that, when
      exponentiated, produces bytes starting with the prefix - which is enough
      for a lax verifier that only checks the start of the decrypted block

This script contains:
  - a vulnerable `lax_verify` that only checks the prefix
  - a `forge_signature_lax` that builds the forged signature
  - a `strict_verify` using pycryptodome's pkcs1_15 for comparison

Usage:  python3 e3_signature_forgery.py
"""

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import base64

# ASN.1 prefix for SHA-256 DigestInfo: 
# SEQUENCE { AlgorithmIdentifier sha256, NULL }, OCTET STRING (32 bytes)
ASN1_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

def ceil_cube_root(n: int) -> int:
    """Return the integer ceil of the cube root of n."""
    if n < 0:
        raise ValueError("n must be non-negative")
    lo, hi = 0, 1 << ((n.bit_length() + 2) // 3)  # initial upper bound
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid
    return lo

def make_pkcs1_v1_5_block(msg: bytes, key_len: int, num_ff: int = 8) -> bytes:
    """
    Build a minimal PKCS#1 v1.5 encoded block for SHA-256:
    0x00 || 0x01 || PS (0xff * num_ff) || 0x00 || ASN1 || H
    This intentionally uses a *short* PS to simulate a lax verifier.
    """
    h = SHA256.new(msg).digest()
    prefix = b'\x00\x01' + (b'\xff' * num_ff) + b'\x00' + ASN1_SHA256 + h
    if len(prefix) > key_len:
        raise ValueError("prefix too long for key length")
    # left-align prefix in a key_len byte block (occupies most significant bytes)
    shift = 8 * (key_len - len(prefix))
    EM_int = int.from_bytes(prefix, 'big') << shift
    return EM_int.to_bytes(key_len, 'big')

def forge_signature_lax(msg: bytes, pub_n: int, key_len: int, e: int = 3, num_ff: int = 8):
    """
    Forge a signature intended to pass a lax verifier:
      1) Build a minimal EM_int with short PS.
      2) Take ceil cube root (for e=3) as initial candidate s.
      3) Try small adjustments around s to find a signature that passes a lax verifier.
    Returns (sig_bytes, discovered_candidate_s).
    """
    # Construct the integer form of the encoded message (left aligned)
    h = SHA256.new(msg).digest()
    prefix = b'\x00\x01' + (b'\xff' * num_ff) + b'\x00' + ASN1_SHA256 + h
    shift = 8 * (key_len - len(prefix))
    EM_int = int.from_bytes(prefix, 'big') << shift

    # initial cube root guess
    s0 = ceil_cube_root(EM_int)

    # We will search around s0 for a candidate that makes pow(s, e, n) start with prefix
    # (the vulnerable server uses m = sig^e mod n and checks the first bytes only)
    # Try a small neighborhood.
    SEARCH_RANGE = 10
    for delta in range(0, SEARCH_RANGE):
        for sign in (+1, -1):
            s = s0 + sign * delta
            if s <= 0:
                continue
            sig_int = s
            # server computes m = sig_int**e mod n
            m_int_mod = pow(sig_int, e, pub_n)
            m_bytes = int.to_bytes(m_int_mod, key_len, 'big')
            if m_bytes.startswith(prefix):
                # found a candidate that will pass a lax prefix check
                return int.to_bytes(sig_int, key_len, 'big'), s
    # If nothing found, still return the initial candidate
    return int.to_bytes(s0, key_len, 'big'), s0

def lax_verify(sig_bytes: bytes, msg: bytes, pubkey: RSA.RsaKey, num_ff: int = 8) -> bool:
    """
    Vulnerable verification: only checks that the decrypted 
    block starts with the PKCS#1 v1.5 prefix.
    """
    key_len = pubkey.size_in_bytes()
    sig_int = int.from_bytes(sig_bytes, 'big')
    m_int = pow(sig_int, pubkey.e, pubkey.n)
    m_bytes = int.to_bytes(m_int, key_len, 'big')
    # Reconstruct expected prefix
    h = SHA256.new(msg).digest()
    expected_prefix = b'\x00\x01' + (b'\xff' * num_ff) + b'\x00' + ASN1_SHA256 + h
    return m_bytes.startswith(expected_prefix)

def strict_verify(sig_bytes: bytes, msg: bytes, pubkey: RSA.RsaKey) -> bool:
    """
    Strict verification using pycryptodome's pkcs1_15 (RSA PKCS#1 v1.5).
    This will only return True for fully correct signatures.
    """
    h = SHA256.new(msg)
    try:
        pkcs1_15.new(pubkey).verify(h, sig_bytes)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    # Generate an RSA key with small exponent e=3.
    key_size_bits = 2048; e = 3
    print(f"Generating RSA key {key_size_bits} bits, e={e}.")
    key = RSA.generate(key_size_bits, e=e)
    pub = key.publickey()
    key_len = pub.size_in_bytes()

    # We wants to forge a signature for this message
    msg = b"AESpider"
    print(f"Message to forge: {msg!r}\n")

    print("Forging signature with short PS..")
    sig_bytes, s_candidate = forge_signature_lax(msg, pub.n, key_len, e=e, num_ff=8)
    print(f"Candidate integer s = {s_candidate} ({len(sig_bytes)} bytes)\n")
    print("Signature (base64):", base64.b64encode(sig_bytes).decode())

    # Check against lax verifier
    print("\nLax verification:", lax_verify(sig_bytes, msg, pub, num_ff=8))
    # Check against strict verifier (pycryptodome)
    print("Strict verification:", strict_verify(sig_bytes, msg, pub))
