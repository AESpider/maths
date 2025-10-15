#!/usr/bin/env python3
"""
Wiener attack: recover small private exponent d.
Implements continued fractions and convergents.
"""
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from math import gcd, isqrt

MESSAGE = b"FLAG"
m = bytes_to_long(MESSAGE)

def continued_fraction(a, b):
    cf = []
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a - q * b
    return cf

def convergents(cf):
    nums = [0, 1]
    dens = [1, 0]
    for q in cf:
        nums.append(q * nums[-1] + nums[-2])
        dens.append(q * dens[-1] + dens[-2])
    # skip the initial dummy entry
    return list(zip(nums[2:], dens[2:]))

def wiener(e, n):
    cf = continued_fraction(e, n)
    for (k, d) in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            t = isqrt(disc)
            if t * t == disc:
                return d
    return None

if __name__ == "__main__":
    # create vulnerable RSA with small d
    bits = 256
    while True:
        p = getPrime(bits)
        q = getPrime(bits)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = 12345678901234567  # intentionally small
        if gcd(d, phi) == 1:
            try:
                e = inverse(d, phi)
                c = pow(m, e, n)
                break
            except ValueError:
                continue
    found_d = wiener(e, n)
    if found_d:
        recovered = pow(c, found_d, n)
        print("Found d:", found_d)
        print("Recovered:", long_to_bytes(recovered))
    else:
        print("Wiener failed")
