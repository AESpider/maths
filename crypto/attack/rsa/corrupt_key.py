#!/usr/bin/env sage -python
"""
Coppersmith small-roots for corrupted RSA private key (recover p given high bits).

This script implements the small-roots lattice method (Howgrave-Graham / Coppersmith) 
to recover a prime p when we know its upper 256 bits. It expects to be executed with 
Sage (uses ZZ, Zmod, PolynomialRing, Matrix and LLL provided by Sage).

The parameters may need tuning depending on the target.
  - bits: number of mid-bits we brute-force. Increases brute-force work (2**bits)
           but reduces the unknown lower-part size X (easier for Coppersmith).
  - m: lattice multiplicity parameter (how many multiples/powers of f to include).
           Larger m => richer lattice (higher success chance) but larger LLL cost.
  - beta: success exponent. We search roots x with |x| < N**beta. Beta in (0,1].
           It controls t = floor(delta * m * (1/beta - 1)) and therefore lattice size.

Requirement: sage, tqdm
Usage:  sage -python corrupt_key.py 
"""

from tqdm import tqdm
from sage.all import ZZ, Zmod, PolynomialRing, Matrix, RR, log, lcm

# Target values
n = 0x8036e9cbc8fb135c1bcff34549254e09cd49b3620e4c01b7d8590c66e6ed52f81033fb655e236b2f1e572d405c929e0b26b4159b1669244029362d20c4eeee55d31ffcc1033454ca8fb4427d85fadfb365e7a811cd6bda403a4abc6887b4d070d7397efea51b2493c2c53347613cd641231493c7ce9619882c84a54556e17a95
_p_high = 0x8462df26367cc1d75b7e6a007ac9e0b8cbafe98d0d9244be822bf73eef1ae38d0000000000000000000000000000000000000000000000000000000000000000

# small_roots: lattice construction and LLL
# In sage use f.small_roots(X=X, beta=beta)
def small_roots(f, X, beta=1.0, m=None):
    """
    Find small integer roots of a univariate polynomial modulo N.

    Implements Coppersmith's algorithm (Howgrave-Graham reformulation)
    to find roots x with |x| < X of a polynomial f modulo a factor b of N
    with b >= N^beta.

    Parameters:
        f    : a monic polynomial over Zmod(N) (Sage polynomial)
        X    : bound on |root| (should match 2**shift used in recover)
        beta : parameter in (0,1] controlling success condition
        m    : number of multiplier polynomials to build (if None, heuristics used)

    Returns: list of integer roots (may be empty)
    """
    # Basic parameter retrieval
    N = f.parent().characteristic()
    delta = f.degree()

    # Convert to Sage RealField for precise calculations
    beta = RR(beta)

    # Auto-compute m if not provided
    if m is None:
        # compute epsilon with Sage RR (heuristic to pick m)
        epsilon = RR(beta**2 / f.degree() - log(2*X, N))
        m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
  
    m = int(m)

    # t is number of extra polynomials x^i * f^m (controls lattice size)
    t = int((delta * m * (1 / beta - 1)).floor())

    # Convert polynomial to ZZ and make monic
    fZ = f.change_ring(ZZ).monic()
    P = fZ.parent()
    x = P.gen()
    
    # Build shift polynomials for the lattice 
    # Part 1: x^j * N^(m-i) * f^i for i in [0..m), j in [0..delta)
    g = [x**j * N**(m-i) * fZ**i for i in range(m) for j in range(delta)]
    # Part2: x^i * f^m for i in [0..t)
    g.extend([x**i * fZ**m for i in range(t)])

    # Construct lattice matrix
    B = Matrix(ZZ, len(g), delta*m + max(delta, t))

    # Fill matrix with scaling by X^j
    for i in range(B.nrows()):
        for j in range(g[i].degree() + 1):
            B[i, j] = g[i][j] * X**j

    # LLL reduce the lattice
    B = B.LLL()

    # Reconstruct polynomial from the first LLL row
    # Divide by X^j to recover true coefficients
    f_reduced = sum([ZZ(B[0, i] // X**i) * x**i for i in range(B.ncols())])

    # Filter roots
    roots = set([f_reduced.base_ring()(r) for r, _ in f_reduced.roots() if abs(r) <= X])

    # Search integer roots of the reduced polynomial 
    return [root for root in roots if N.gcd(ZZ(fZ(root))) >= N**beta]


# recover: try to reconstruct p from its high bits
def recover(p_high, n, m, beta=0.4):
    """
    Given p_high (an integer representing the top bits of p shifted to MSB),
    try to recover the full p using small_roots.
      - p_bits is an approximation of p's bit-length (we use n.bit_length() // 2).
      - shift = p_bits - p_high_bits. The unknown low-part x satisfies 0 <= x < 2**shift.
      - f(x) = p_high * 2**shift + x; we search for small roots x of f mod n.
    """
    p_bits = n.bit_length() // 2  # approximate bit-length of p
    p_high_bits = p_high.bit_length()
    PR = PolynomialRing(Zmod(n), 'x')
    x = PR.gen()

    # compute shift (number of unknown low bits)
    shift = p_bits - p_high_bits
    if shift < 0: return None     # unexpected: p_high has more bits than expected

    # f(x) sets x as the unknown lower part; X is the bound on |x|
    f = p_high * 2**shift + x
    X = 2**shift

    # call Coppersmith small_roots with the chosen parameters
    roots = small_roots(f, X=X, beta=beta, m=m)
    if not roots:
        return None

    # f evaluated at root gives candidate p (in integer range)
    p_candidate = int(f(roots[0]))
    return p_candidate


# solve: brute-force a few mid bits, call recover
def solve(bits: int, m: int):
    """
    Brute-force `bits` mid choices and call recover() for each candidate.
    We construct trial _p values by inserting the guessed mid-bits into _p_high.
    Returns recovered p or None.
    """
    for x in tqdm(range(2**bits)):
        # add the guessed delta (x) shifted to the known _p_high area
        _p = _p_high + x * 2**(256 - bits)

        # take the top (256 + bits) bits of _p as p_high
        bin_str = bin(_p)[2:]
        # ensure we have at least that many bits (pad if necessary)
        if len(bin_str) < (256 + bits):
            bin_str = bin_str.ljust(256 + bits, '0')
        p_high = int(bin_str[:256 + bits], 2)

        # try to recover using small_roots
        p = recover(p_high, n, m)
        if p: return p
    return None


if __name__ == "__main__":
    print("Recovered corrupted RSA private key using Coppersmith small-roots + LLL\n")
    # bits: how many mid-bits to brute-force (2^bits)
    # m: lattice parameter 

    p = solve(bits=9, m=16)
    if p:
        print("\nRecovered p:", hex(p))

        # checks
        if ZZ(p).is_prime(): print("p is prime !")
        else: print("p is NOT prime")

        if n % p == 0: print(f"p divides n, q = {hex(n // p)}")
        else: print("p does NOT divide n")
    else:
        print("p not found with current parameters")
