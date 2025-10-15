#!/usr/bin/env python3
"""
Fermat factorization for close primes.
Works well when p and q are close to each other.
"""
from Crypto.Util.number import bytes_to_long, long_to_bytes
from math import isqrt

MESSAGE = b"FLAG"
m = bytes_to_long(MESSAGE)

if __name__ == "__main__":
    # fixed close primes
    p = 10000000019
    q = 10000000033
    n = p * q
    e = 65537
    # compute ciphertext (we assume phi invertible)
    from Crypto.Util.number import inverse
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    c = pow(m, e, n)
    # Fermat's method
    a = isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    while isqrt(b2)**2 != b2:
        a += 1
        b2 = a * a - n
    b = isqrt(b2)
    p_found = a - b
    q_found = a + b
    # recover
    phi_rec = (p_found - 1) * (q_found - 1)
    d_rec = inverse(e, phi_rec)
    recovered = pow(c, d_rec, n)
    print("Found primes:", p_found, q_found)
    print("Recovered:", long_to_bytes(recovered))
