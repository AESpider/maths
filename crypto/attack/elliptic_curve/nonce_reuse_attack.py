#!/usr/bin/env python3
"""
ECDSA nonce-reuse attack (secp256k1).

Shows how reusing the same nonce k for two ECDSA signatures 
on different messages leaks the private key.

Given two signatures (r, s1) and (r, s2) on messages m1 and m2 that reuse the
same nonce k, one can compute:

    k = (h1 - h2) * inv(s1 - s2)  (mod n)
    d = (s1 * k - h1) * inv(r)   (mod n)

where h1,h2 are the SHA-256 message digests interpreted as integers modulo n.

Usage: python3 nonce_reuse_attack.py
"""

from hashlib import sha256
import os
from typing import Tuple

# secp256k1 curve parameters
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# finite-field helpers
def inv_mod(x: int, m: int) -> int:
    """Modular inverse for Python 3.8+"""
    return pow(x, -1, m)

# EC point arithmetic (affine coordinates)
def is_infinite(Pt: Tuple[int,int] | None) -> bool:
    return Pt is None

def point_add(P1: Tuple[int,int] | None, P2: Tuple[int,int] | None) -> Tuple[int,int] | None:
    """Add two points on the curve (affine). Handles point at infinity as None."""
    if is_infinite(P1):
        return P2
    if is_infinite(P2):
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None  # P + (-P) = infinity
    if x1 == x2:
        # point doubling
        lam = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mul(k: int, point: Tuple[int,int]) -> Tuple[int,int] | None:
    """Scalar multiplication (double-and-add)."""
    if k % N == 0 or is_infinite(point):
        return None
    if k < 0:
        # k * P = -k * (-P)
        return scalar_mul(-k, (point[0], (-point[1]) % P))
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ECDSA primitives (sign/verify)
def sha256_int(msg: bytes) -> int:
    return int.from_bytes(sha256(msg).digest(), 'big')

def ecdsa_sign(msg: bytes, priv: int, k: int) -> Tuple[int,int]:
    """
    Produce ECDSA signature (r, s) using provided nonce k.
      r = (k*G).x mod n
      s = k^{-1} * (h + r*priv) mod n
    """
    R = scalar_mul(k, (Gx, Gy))
    assert R is not None
    r = R[0] % N
    if r == 0:
        raise ValueError("r == 0, pick different k")
    h = sha256_int(msg) % N
    s = (inv_mod(k, N) * (h + r * priv)) % N
    if s == 0:
        raise ValueError("s == 0, pick different k")
    return r, s

def ecdsa_verify(msg: bytes, pub: Tuple[int,int], sig: Tuple[int,int]) -> bool:
    """Basic ECDSA verification"""
    r, s = sig
    if not (1 <= r < N and 1 <= s < N):
        return False
    h = sha256_int(msg) % N
    w = inv_mod(s, N)
    u1 = (h * w) % N
    u2 = (r * w) % N
    P = point_add(scalar_mul(u1, (Gx, Gy)), scalar_mul(u2, pub))
    if is_infinite(P):
        return False
    return (P[0] % N) == r

def nonce_reuse_attack(sig1: Tuple[int,int], sig2: Tuple[int,int], h1: int, h2: int) -> int:
    """
    Given two signatures (r, s1) and (r, s2) that reused the same nonce k,
    recover the private key d.
    Steps:
      k = (h1 - h2) * inv(s1 - s2) mod n
      d = (s1*k - h1) * inv(r) mod n
    """
    r, s1 = sig1
    _, s2 = sig2
    if r == 0:
        raise ValueError("Invalid r")
    s_diff = (s1 - s2) % N
    if s_diff == 0:
        raise ValueError("s1 == s2, cannot recover k")
    k = ((h1 - h2) * inv_mod(s_diff, N)) % N
    d = ((s1 * k - h1) * inv_mod(r, N)) % N
    return d

if __name__ == "__main__":
    print("ECDSA nonce-reuse attack (secp256k1)\n")
    
    # Generate key
    key = int.from_bytes(os.urandom(32), 'big') % N
    pub = scalar_mul(key, (Gx, Gy))
    print(f"[+] Generated private key d, public key (x,y):")
    print(f"    pub.x = {hex(pub[0])}")
    print(f"    pub.y = {hex(pub[1])}\n")

    # Create two messages and intentionally reuse the same nonce k
    msg1 = b"Two signatures, one nonce, zero secrets"
    msg2 = b"f4k3_f0r_t3st1ng"

    # choose a nonce k 
    bad_k = int.from_bytes(os.urandom(32), 'big') % N

    r1, s1 = ecdsa_sign(msg1, key, bad_k)
    r2, s2 = ecdsa_sign(msg2, key, bad_k)
    h1 = sha256_int(msg1) % N
    h2 = sha256_int(msg2) % N

    print("[+] Two signatures reusing the same nonce k:")
    print(f"    r  = {hex(r1)}")
    print(f"    s1 = {hex(s1)}")
    print(f"    s2 = {hex(s2)}\n")

    # 3) Attack: recover private key from the two signatures
    recovered_d = nonce_reuse_attack((r1, s1), (r2, s2), h1, h2)
    print(f"[+] Recovered private key d: {hex(recovered_d)}")

    print(f"[+] Match ? {recovered_d == key}")
