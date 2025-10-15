#!/usr/bin/env python3
"""
Low exponent attack (e=3).
This script ensures m^3 < n so the message can be recovered by integer cube root.
"""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from math import gcd

MESSAGE = b"FLAG"
m = bytes_to_long(MESSAGE)

def int_nth_root(x, n):
    """Integer nth root using binary search: returns floor(root)."""
    lo, hi = 0, 1 << ((x.bit_length() // n) + 2)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**n <= x:
            lo = mid
        else:
            hi = mid
    return lo

if __name__ == "__main__":
    e = 3
    # find modulus so that m^3 < n
    while True:
        p = getPrime(80)
        q = getPrime(80)
        n = p * q
        if n > m**e and gcd(m, n) == 1:
            break
    c = pow(m, e, n)
    # attack: since m^e < n, c == m^e as integers
    root = int_nth_root(c, e)
    # refine/check
    assert root**e == c
    print("Recovered:", long_to_bytes(root))
