#!/usr/bin/env python3
"""
Hastad's broadcast attack for e=3.
Collect 3 ciphertexts (same message) under co-prime moduli and recover message.
"""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
from math import gcd

MESSAGE = b"FLAG"
m = bytes_to_long(MESSAGE)

def crt(c_list, n_list):
    total = 0
    prod = 1
    for n in n_list:
        prod *= n
    for c, n in zip(c_list, n_list):
        p = prod // n
        total += c * inverse(p, n) * p
    return total % prod

def int_nth_root(x, n):
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
    moduli = []
    cs = []
    for _ in range(3):
        while True:
            p = getPrime(64); q = getPrime(64)
            n = p * q
            if gcd(m, n) == 1:
                break
        moduli.append(n)
        cs.append(pow(m, e, n))
    M = crt(cs, moduli)
    root = int_nth_root(M, e)
    assert root**e == M
    print("Recovered:", long_to_bytes(root))
