#!/usr/bin/env python3

import math
from collections import defaultdict

# List of all primes < 1000
PRIMES_UNDER_1000 = [
    2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
   31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
   73,  79,  83,  89,  97, 101, 103, 107, 109, 113,
  127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
  179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
  233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
  283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
  353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
  419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
  467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
  547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
  607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
  661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
  739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
  811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
  877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
  947, 953, 967, 971, 977, 983, 991, 997
]

def factorize_smooth_number(n):
    """Factorize n by trial division using all primes < 1000"""
    factors = defaultdict(int)
    remaining = n
    for p in PRIMES_UNDER_1000:
        if p * p > remaining:
            break
        while remaining % p == 0:
            factors[p] += 1
            remaining //= p
    if remaining > 1:
        # remaining may be a prime > 1000 or a composite made of larger primes
        factors[remaining] += 1
    return dict(factors)

def mod_exp(base, exp, mod):
    """Efficient modular exponentiation"""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def baby_step_giant_step(g, h, p, max_steps=None):
    """Baby-step giant-step algorithm to solve g^x = h (mod p)"""
    if max_steps is None:
        max_steps = int(math.sqrt(p)) + 1
    
    # Baby steps: compute g^j for j = 0, 1, ..., m-1
    baby_steps = {}
    current = 1
    for j in range(max_steps):
        if current == h:
            return j
        baby_steps[current] = j
        current = (current * g) % p
    
    # Giant steps
    gamma = mod_exp(g, max_steps, p)
    gamma_inv = mod_exp(gamma, p - 2, p)  # modular inverse
    
    y = h
    for i in range(max_steps):
        if y in baby_steps:
            return i * max_steps + baby_steps[y]
        y = (y * gamma_inv) % p
    
    return None

def solve_dlp_prime_power(g, h, p, q, e):
    """Solve the DLP in a subgroup of order q^e"""
    order = q ** e
    
    # Simple case: brute-force if q^e is small
    if order <= 10000:
        for x in range(order):
            if mod_exp(g, x, p) == h:
                return x
    
    # Otherwise, use baby-step giant-step
    return baby_step_giant_step(g, h, p, int(math.sqrt(order)) + 1)

def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def chinese_remainder_theorem(remainders, moduli):
    """Chinese Remainder Theorem"""
    total = 0
    prod = 1
    for m in moduli:
        prod *= m
    
    for r, m in zip(remainders, moduli):
        p = prod // m
        _, inv, _ = extended_gcd(p, m)
        total += r * inv * p
    
    return total % prod

def pohlig_hellman(g, y, p, verbose=False):
    """Pohlig-Hellman algorithm to solve y = g^x (mod p)"""
    p_minus_1 = p - 1 # factor p-1
    factors = factorize_smooth_number(p_minus_1)
    
    factor_list = [f"{prime}^{exp}" for prime, exp in factors.items()]
    print(f"Factorization of p-1:  [{', '.join(factor_list)}]")

    remainders = []
    moduli = []
    
    # For each prime power q^e dividing p-1
    for q, e in factors.items():
        qe = q ** e
        print(f"\nProcessing factor {q}^{e} = {qe}")
        
        # Compute g_i = g^((p-1)/q^e) mod p
        exponent = p_minus_1 // qe
        g_i = mod_exp(g, exponent, p)
        h_i = mod_exp(y, exponent, p)
        
        if verbose:
            print(f"  g_i = g^{exponent} mod p = {g_i}")
            print(f"  h_i = y^{exponent} mod p = {h_i}")
        
        # Solve g_i^x_i = h_i (mod p) in subgroup of order q^e
        if g_i == 1 and h_i == 1:
            x_i = 0
        else:
            x_i = solve_dlp_prime_power(g_i, h_i, p, q, e)
        
        if x_i is None:
            print(f"  Failed to solve DLP modulo {qe}")
            return None
        
        print(f"  Partial solution: x = {x_i} (mod {qe})")
        
        remainders.append(x_i)
        moduli.append(qe)
    
    # Combine solutions with CRT
    print(f"\nCombining partial solutions with CRT:\n")
    print(f"Remainders: {remainders}\n")
    print(f"Moduli: {moduli}")
    
    x = chinese_remainder_theorem(remainders, moduli)
    return x

if __name__ == "__main__":
    # Problem data: p-1 is smooth (its prime factors are small)
    p = 94487163297382863167633060898467898176295383252944606346612565696030376662261885354113923956999751538280705847409180073365038322172781858474622022808482972630746560742341702742178330138682963971041358923639916031988458406627047092978738794000171785975693222202416488063109972907266960217738849683470100180657
    y = 80905650118846385931764925970457972889929953376763445484237320000327884329168934728928081077667420611873474478780456122831059312737019466367282871744034214492809575109792401639770538955432531764305943142688619101553963448240387184302532415259921365582743379207582614300826999903808215005060226437928891565763
    g = 91837172179571476776190849460700915868439517079156440218651607148606324494298737979207246124168621805457673911794964841647324903434381292641072254574996422082928102274796072341535153901982527988318666060710699023247733315763656131213319397976417698616067127741385175318280373623657263470144195815929916049604

    print("Discrete Logarithm resolution with Pohlig-Hellman (p-1 is smooth)\n")
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"y = {y}\n")
    print(f"Searching for x such that g^x = y (mod p)\n")

    # Solve with Pohlig-Hellman
    x = pohlig_hellman(g, y, p, verbose=False)

    if x is not None:
        print(f"\nSOLUTION FOUND!!")
        print(f"  x = {x}\n")
    
        # Verification
        verification = mod_exp(g, x, p)
        print(f"g^x = y mod p ? {verification == y}\n")

        # x bits
        x_bits = x.bit_length()
        print(f"Number of bits of x: {x_bits}")
        print(f"x in hex: {hex(x)}")
    else:
        print("Failed to solve")
