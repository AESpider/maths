#!/usr/bin/env python3
"""
Common modulus attack.
Same modulus n, two different exponents e1, e2, same plaintext m.
"""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
from math import gcd

MESSAGE = b"FLAG"
m = bytes_to_long(MESSAGE)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, x1, y1 = egcd(b % a, a)
    return (g, y1 - (b // a) * x1, x1)

if __name__ == "__main__":
    # shared modulus
    p = getPrime(64)
    q = getPrime(64)
    n = p * q
    e1 = 65537
    e2 = 65521
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    g, u, v = egcd(e1, e2)
    assert g == 1
    if v < 0:
        c2 = inverse(c2, n)
        v = -v
        m_rec = (pow(c1, u, n) * pow(c2, v, n)) % n
    else:
        m_rec = (pow(c1, u, n) * pow(c2, v, n)) % n
    print("Recovered:", long_to_bytes(m_rec))
