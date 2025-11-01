#!/usr/bin/env python3
"""
Bleichenbacher PKCS#1 v1.5 padding-oracle attack.

This script demonstrates the core idea of Bleichenbacher's chosen-ciphertext
attack against RSA PKCS#1 v1.5 padding using a padding oracle.

  1. Obtain a conformant ciphertext (blinding s0).
  2. Search multiplicative factors s_i with the oracle.
  3. Refine intervals on the plaintext until a unique solution is found.
  4. Recover the original message by unblinding.

Small key sizes by default to keep the demo fast.

Usage: python3 bleichenbacher_attack.py
"""

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long

# set to 128 or 256 to use hardcoded keys; other values will call RSA.generate()
KEY_BITS = 256

# 128-bit key
_128_n = 0xa75955c33c3a950caa693d52688c4d19
_128_e = 65537
_128_d = 0x3f7b8f2221cde34e2d3edd1d82f31b91
_128_p = 0xecb899b84ed5ba2d
_128_q = 0xb4fa6502ea5ece1d

# 256-bit key
_256_n = 0x86494d70f02977a9e8070fe8c61e24c26075e04ca06e1f18b3cdd52b9949a1a9
_256_e = 65537
_256_d = 0x5f7f9bda388154ff78ea24cf46adc3378c63af44034f87d515900c01e2a469b1
_256_p = 0xc6d3f33fe8b98db8278bfe8b1e3381e5
_256_q = 0xace6570468cf67945bd3b61c391df475

# helpers
def ceil_div(a, b):
    return -(-a // b)

def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b, x0, x1, y0, y1 = b, a - q*b, x1, x0 - q*x1, y1, y0 - q*y1
    return x0, y0, a

def inv_mod(x, m):
    u, v, g = egcd(x, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return u % m

# PKCS#1 v1.5 padding helpers
def pkcs1_v15_pad(message: bytes, k: int) -> bytes:
    """Return EM = 0x00 || 0x02 || PS || 0x00 || message, where PS is non-zero bytes."""
    if len(message) > k - 11:
        raise ValueError("message too long for PKCS#1 v1.5")
    ps_len = k - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = get_random_bytes(1)[0]
        if b != 0:
            ps.append(b)
    return b'\x00\x02' + bytes(ps) + b'\x00' + message

def unpad_pkcs1_v15(block: bytes) -> bytes:
    """Return message if block is a valid PKCS#1 v1.5 EM, otherwise None."""
    if len(block) < 11:
        return None
    if block[0:2] != b'\x00\x02':
        return None
    # locate 0x00 after PS
    try:
        idx = block.index(b'\x00', 2)
    except ValueError:
        return None
    return block[idx+1:]

# Oracle
class LocalOracle:
    def __init__(self, rsa_key):
        self._key = rsa_key
        self.n = rsa_key.n
        self.d = rsa_key.d
        self.k = (rsa_key.n.bit_length() + 7) // 8

    def is_pkcs1_v15_conformant(self, ciphertext_int: int) -> bool:
        """Oracle: return True when decrypted block starts with 0x00 0x02"""
        m = pow(ciphertext_int, self.d, self.n)
        block = long_to_bytes(m, self.k)
        return block[0:2] == b'\x00\x02'

# Bleichenbacher attack
def bleichenbacher_attack(cipher_int: int, oracle: LocalOracle, pub_e: int, pub_n: int, max_iters=2000, verbose=False):
    k = oracle.k
    B = 2 ** (8 * (k - 2))
    B2 = 2 * B
    B3 = 3 * B

    # Step 1: Blinding. For demo we usually pick s0 = 1 if ciphertext itself is conformant.
    s0 = 1
    c0 = (cipher_int * pow(s0, pub_e, pub_n)) % pub_n
    if not oracle.is_pkcs1_v15_conformant(c0):
        # find s0 such that c0 is conformant
        s0 = 2
        while True:
            c0 = (cipher_int * pow(s0, pub_e, pub_n)) % pub_n
            if oracle.is_pkcs1_v15_conformant(c0):
                break
            s0 += 1

    # Step 2.a: find first s >= ceil(n / (3B))
    def find_first_s(start):
        s = start
        tries = 0
        while True:
            ci = (c0 * pow(s, pub_e, pub_n)) % pub_n
            if oracle.is_pkcs1_v15_conformant(ci):
                return s
            s += 1
            tries += 1
            if tries % 50000 == 0:
                print(f"    tried {tries} values for s (current {s})")

    s = ceil_div(pub_n, 3 * B)
    s = find_first_s(s)
    # initial interval M = [(2B, 3B-1)]
    M = [(B2, B3 - 1)]
    iteration = 1

    while iteration <= max_iters:
        # Step 2.b / 2.c: find next s depending on number of intervals
        if len(M) > 1:
            s = find_first_s(s + 1)
        else:
            # single interval optimization
            a, b = M[0]
            # search for r then s
            r = ceil_div(2 * (b * s - B2), pub_n)  # starting r
            found = False
            while not found:
                low = ceil_div(B2 + r * pub_n, b)
                high = (B3 - 1 + r * pub_n) // a
                if low <= high:
                    for si in range(low, high + 1):
                        ci = (c0 * pow(si, pub_e, pub_n)) % pub_n
                        if oracle.is_pkcs1_v15_conformant(ci):
                            s = si
                            found = True
                            break
                r += 1

        # Step 3: refine intervals
        newM = []
        for (a, b) in M:
            rmin = ceil_div(a * s - B3 + 1, pub_n)
            rmax = (b * s - B2) // pub_n
            for r in range(rmin, rmax + 1):
                newa = max(a, ceil_div(B2 + r * pub_n, s))
                newb = min(b, (B3 - 1 + r * pub_n) // s)
                if newa <= newb:
                    newM.append((newa, newb))
        M = newM

        if verbose: print(f"  iter {iteration}: s={s}, intervals={len(M)}")

        # Step 4: termination
        if len(M) == 1:
            a, b = M[0]
            if a == b:
                # recovered m0 = a * s0^{-1} mod n
                m_recovered = (a * inv_mod(s0, pub_n)) % pub_n
                return m_recovered
        iteration += 1

    raise RuntimeError("attack did not converge within max_iters")

if __name__ == "__main__":
    # Generate RSA key
    if KEY_BITS == 128:
        key = RSA.construct((_128_n, _128_e, _128_d, _128_p, _128_q))
    elif KEY_BITS == 256:
        key = RSA.construct((_256_n, _256_e, _256_d, _256_p, _256_q))
    else:
        key = RSA.generate(KEY_BITS)

    pub_n = key.n
    pub_e = key.e
    oracle = LocalOracle(key)

    # message and padding
    message = b"AESpider"
    k_bytes = oracle.k
    print(f"Key size: {KEY_BITS} bits, modulus length: {k_bytes} bytes\n")
    EM = pkcs1_v15_pad(message, k_bytes)
    m_int = bytes_to_long(EM)
    ciphertext_int = pow(m_int, pub_e, pub_n)

    # check
    assert oracle.is_pkcs1_v15_conformant(ciphertext_int)

    print("Running Bleichenbacher attack..")
    recovered_m_int = bleichenbacher_attack(ciphertext_int, oracle, pub_e, pub_n, max_iters=2000, verbose=True)
    recovered_bytes = long_to_bytes(recovered_m_int, k_bytes)
    recovered_msg = unpad_pkcs1_v15(recovered_bytes)
    print("\nRecovered message:", recovered_msg.decode())
    print("Match ?", message==recovered_msg)
