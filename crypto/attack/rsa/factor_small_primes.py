#!/usr/bin/env python3
"""
Uses Pollard's Rho to factor a weak RSA modulus (small primes).
"""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from math import gcd
import random

MESSAGE = b"FLAG"
m = bytes_to_long(MESSAGE)

def pollards_rho(n):
    """Pollard's Rho for a non-trivial factor of n (probabilistic)."""
    if n % 2 == 0:
        return 2
    while True:
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
            if d == n:
                break
        if 1 < d < n:
            return d

if __name__ == "__main__":
    # generate weak RSA with small primes (32 bits)
    p = getPrime(32)
    q = getPrime(32)
    n = p * q
    e = 65537
    c = pow(m, e, n)
    print("n (weak) =", n)
    # attack: factor n
    f = pollards_rho(n)
    p_found = f
    q_found = n // f
    print("factors:", p_found, q_found)

    # recover message
    from Crypto.Util.number import inverse
    phi = (p_found - 1) * (q_found - 1)
    d = inverse(e, phi)
    recovered = pow(c, d, n)
    print("Recovered:", long_to_bytes(recovered))
