#!/usr/bin/env python3
"""
Known-factor RSA decryption helper.

- If p and q are provided: compute phi, d and decrypt c.
- Otherwise try FactorDB API: https://factordb.com/api?query=<N>

Dependencies:
    pip install pycryptodome requests
"""
import argparse
import json
from Crypto.Util.number import long_to_bytes, inverse
import requests
from math import prod

API = "https://factordb.com/api?query="

def query_factordb(n: int):
    """Query FactorDB API and return list of prime factors (with multiplicity) or None."""
    r = requests.get(API + str(n), timeout=10)
    if r.status_code != 200:
        return None
    j = r.json()
    # 'factors' is a list of [factor_string, multiplicity_string]
    if "factors" not in j:
        return None
    factors = []
    for f, mult in j["factors"]:
        for _ in range(int(mult)):
            factors.append(int(f))
    return factors

def try_recover_from_pq(n, p, q, e, c):
    """Given p,q compute phi,d and optionally decrypt c if provided."""
    print(f"Known factors: p={p}, q={q}")
    if p * q != n:
        raise SystemExit("Error: p * q != N")
    phi = (p - 1) * (q - 1)
    print(f"phi = {phi}")
    d = inverse(e, phi)
    print(f"d  = {d}")
    if c is None:
        print("No ciphertext provided (c), stopping after showing d.")
        return None

    # decrypt
    m = pow(c, d, n)
    m_bytes = long_to_bytes(m)
    m_int = m
    m_hex = m_bytes.hex()

    print("Recovered plaintext:")
    print(f"  bytes : {m_bytes}")
    print(f"  int   : {m_int}")
    print(f"  hex   : 0x{m_hex}")
    return m

def choose_factors_from_list(n, flist):
    """Try to pick two factors from flist that multiply to n (return (p,q) or None)."""
    # common case: flist == [p, q]
    if len(flist) == 2 and flist[0] * flist[1] == n:
        return (flist[0], flist[1])
    # try all pairs (works when DB returns many prime factors)
    L = flist
    for i in range(len(L)):
        for j in range(i + 1, len(L)):
            if L[i] * L[j] == n:
                return (L[i], L[j])
    return None

def main():
    parser = argparse.ArgumentParser(description="Decrypt RSA using known factors or FactorDB lookup.")
    parser.add_argument("-N", "--modulus", required=True, help="RSA modulus N (decimal).")
    parser.add_argument("-c", "--cipher", type=int, help="Ciphertext c (decimal).")
    parser.add_argument("--p", type=int, help="Prime factor p (optional).")
    parser.add_argument("--q", type=int, help="Prime factor q (optional).")
    parser.add_argument("-e", "--exponent", type=int, default=65537, help="Public exponent (default 65537).")
    args = parser.parse_args()

    N = int(args.modulus)
    c = args.cipher
    e = int(args.exponent)

    # If p and q provided, use them
    if args.p and args.q:
        try_recover_from_pq(N, int(args.p), int(args.q), e, c)
        return

    # Try FactorDB
    print(f"Querying FactorDB for N={N} ...")
    factors = query_factordb(N)
    if not factors:
        raise SystemExit("FactorDB query failed or no factorization found.")
    print("Factors returned by FactorDB:", factors)

    pq = choose_factors_from_list(N, factors)
    if pq:
        p, q = pq
        try_recover_from_pq(N, p, q, e, c)
    else:
        raise SystemExit("Could not pick p,q from FactorDB factors. Manual inspection required.")

if __name__ == "__main__":
    main()
