#!/usr/bin/env python3
"""
Chosen ciphertext (multiplicative) oracle.
Simulates an oracle that will decrypt modified ciphertexts.
"""
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse

MESSAGE = b"FLAG"
m = bytes_to_long(MESSAGE)

if __name__ == "__main__":
    p = getPrime(64); q = getPrime(64)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    c = pow(m, e, n)
    # attacker crafts c' = c * (2^e) mod n and sends to oracle
    c2 = pow(2, e, n)
    c_prime = (c * c2) % n
    # oracle (simulated) decrypts c'
    m_times_2 = pow(c_prime, d, n)
    # attacker computes inverse(2) and recovers m
    m_rec = (m_times_2 * inverse(2, n)) % n
    print("Recovered:", long_to_bytes(m_rec))
