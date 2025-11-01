#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ElGamal ECC single-bit fault attack on the private scalar used in decryption.

A single bit of the private x is flipped (x' = x XOR 2^b). This yields a faulty 
plaintext M_fault such that:  
  
  D = M_fault - M_ref = (x - x') * c1 = delta * c1, where delta = ±2^b (modulo the curve order).

Comparing D with small powers of two times c1 allows recovering the flipped bit position and value.

Principle:
  1. Obtain M_ref = Dec(c) (no fault) and many M_fault = Dec(c) with single-bit faults.
  2. Compute D = M_fault - M_ref for each faulty run.
  3. For each bit position b, check if D ==  2^b * c1  (original bit was 1) or
      D == (n - 2^b) * c1  (original bit was 0 modulo order).
  4. Accumulate recovered bits and brute-force remaining bits if necessary.

Usage:  python3 elgamal_fault_attack.py
"""

import random
from typing import Optional, Tuple

# Curve parameters (secp256k1)
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# Point and curve arithmetic (affine coords)
class Point:
    def __init__(self, x: Optional[int], y: Optional[int]):
        self.x = x
        self.y = y
        self.infinity = (x is None and y is None)

    def __eq__(self, other: 'Point') -> bool:
        if self.infinity and other.infinity:
            return True
        if self.infinity or other.infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __str__(self) -> str:
        return 'INF' if self.infinity else f'({self.x},{self.y})'

    @classmethod
    def inf(cls):
        return cls(None, None)

class Curve:
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p

    def is_on_curve(self, P: Point) -> bool:
        if P.infinity:
            return True
        return (P.y * P.y - (P.x**3 + self.a * P.x + self.b)) % self.p == 0

    def inv(self, x: int) -> int:
        return pow(x, self.p - 2, self.p)

    def point_neg(self, P: Point) -> Point:
        if P.infinity:
            return P
        return Point(P.x, (-P.y) % self.p)

    def point_add(self, P: Point, Q: Point) -> Point:
        if P.infinity:
            return Q
        if Q.infinity:
            return P
        if P.x == Q.x and (P.y != Q.y or P.y == 0):
            return Point.inf()
        if P == Q:
            # slope = (3*x^2 + a) / (2*y)
            s = (3 * P.x * P.x + self.a) * self.inv((2 * P.y) % self.p) % self.p
        else:
            s = (Q.y - P.y) * self.inv((Q.x - P.x) % self.p) % self.p
        xr = (s * s - P.x - Q.x) % self.p
        yr = (s * (P.x - xr) - P.y) % self.p
        return Point(xr, yr)

    def scalar_mul(self, k: int, P: Point) -> Point:
        if k == 0 or P.infinity:
            return Point.inf()
        if k < 0:
            return self.scalar_mul(-k, self.point_neg(P))
        R = Point.inf()
        Q = P
        while k:
            if k & 1:
                R = self.point_add(R, Q)
            Q = self.point_add(Q, Q)
            k >>= 1
        return R

# ElGamal ECC implementation
class ElGamal:
    def __init__(self, curve: Curve, G: Point):
        self.curve = curve
        self.G = G
        self.n = CURVE_ORDER
        self.x = self.x = random.randrange(1, self.n)   # choose private key in [1, n-1]
        self.Q = self.curve.scalar_mul(self.x, self.G)
        # store last fault info for analysis
        self.last_fault = None

    def encrypt(self, M: Point) -> Tuple[Point, Point]:
        k = random.randrange(1, self.n)
        c1 = self.curve.scalar_mul(k, self.G)
        c2 = self.curve.point_add(self.curve.scalar_mul(k, self.Q), M)
        return c1, c2

    def decrypt(self, ciphertext: Tuple[Point, Point], inject_fault: bool = False) -> Point:
        c1, c2 = ciphertext
        x_used = self.x
        if inject_fault:
            # flip one random bit in private key
            pos = random.randrange(0, self.x.bit_length())
            x_used = self.x ^ (1 << pos)
            self.last_fault = {'pos': pos, 'x_faulty': x_used}
        else:
            self.last_fault = None
        s = self.curve.scalar_mul(x_used, c1)
        s_neg = self.curve.point_neg(s)
        M = self.curve.point_add(c2, s_neg)
        return M

# Attack analyzer
class FaultAttack:
    def __init__(self, scheme: ElGamal):
        self.scheme = scheme
        self.recovered = {}  # pos -> bit

    def attack(self, ciphertext: Tuple[Point, Point], trials: int = 1000):
        print("Recovering bit positions...")

        c1, c2 = ciphertext
        # get reference decryption (no fault)
        M_ref = self.scheme.decrypt(ciphertext, inject_fault=False)

        for t in range(trials+1):
            M_fault = self.scheme.decrypt(ciphertext, inject_fault=True)
            if not self.scheme.last_fault: continue
            pos = self.scheme.last_fault['pos']
            # compute difference D = M_fault - M_ref
            D = self.curve_point_sub(M_fault, M_ref)
            # try to match D = delta * c1 where delta = +/- 2^pos
            # positive case: scalar_mul(2^pos, c1) == D -> original bit was 1
            # negative case: scalar_mul(n - 2^pos, c1) == D -> original bit was 0
            two_pow = 1 << pos
            cand_pos = self.scheme.curve.scalar_mul(two_pow, c1)
            if cand_pos == D:
                self.recovered[pos] = 1
            else:
                cand_neg = self.scheme.curve.scalar_mul((self.scheme.n - two_pow) % self.scheme.n, c1)
                if cand_neg == D:
                    self.recovered[pos] = 0
            
            # small progress print
            if t % 100 == 0 and t > 0: print(f"  [+] Tried {t} faults, recovered {len(self.recovered)} bits")

    # P - Q = P + (-Q)            
    def curve_point_sub(self, P: Point, Q: Point) -> Point:
        return self.scheme.curve.point_add(P, self.scheme.curve.point_neg(Q))
    
    # assemble integer from recovered bits (bit 0 = LSB)
    def reconstruct(self) -> int:
        key = 0
        for pos, bit in self.recovered.items():
            if bit:
                key |= (1 << pos)
        return key


def brute_force_missing(base: int, missing: list, scheme: ElGamal, ciphertext: Tuple[Point, Point], M: Point) -> int:
    c1, c2 = ciphertext
    for comb in range(1 << len(missing)):
        cand = base
        for i, pos in enumerate(missing):
            if (comb >> i) & 1:
                cand |= (1 << pos)
        # test candidate by decrypting
        s = scheme.curve.scalar_mul(cand, c1)
        M_cand = scheme.curve.point_add(c2, scheme.curve.point_neg(s))
        if M_cand == M:
            return cand
    return base

# Fault attack
if __name__ == '__main__':
    curve = Curve(A, B, P)
    G = Point(Gx, Gy)
    assert curve.is_on_curve(G), "G is not on curve"

    print("ElGamal ECC single-bit fault attack on private key (decryption)\n")

    scheme = ElGamal(curve, G)
    print(f"Private key: {scheme.x}")
    print(f"Order      : {scheme.n}\n")

    # choose a message as a point: M = m*G
    m_scalar = random.randrange(2, scheme.n)
    M = curve.scalar_mul(m_scalar, G)
    
    ciphertext = scheme.encrypt(M)

    trials = 1000
    print(f"Starting attack with trials: {trials}")
    attacker = FaultAttack(scheme)
    attacker.attack(ciphertext, trials=trials)

    recovered_partial = attacker.reconstruct()
    print(f"\nRecovered partial key: {recovered_partial}")

    # If few bits are missing, brute force the missing ones
    known_positions = set(attacker.recovered.keys())
    bits_total = scheme.x.bit_length()
    missing = [i for i in range(bits_total) if i not in known_positions]
    if len(missing) <= 10:
        print(f"Brute forcing {len(missing)} missing bits...")
        found = brute_force_missing(recovered_partial, missing, scheme, ciphertext, M)
        print(f"Found key: {found}")
        print(f"Match ? {found == scheme.x}")
    else:
        print(f"Too many missing bits to brute-force ({len(missing)})")
