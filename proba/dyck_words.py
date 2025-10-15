#!/usr/bin/env python3
"""
Generating and analyzing Dyck words, Catalan numbers, 
permutations, and combinatorial sequences.

Convention: 1 = open parenthesis, 0 = close parenthesis
"""

from typing import Tuple, List, Generator
import math

# ---------- Combinatorics helpers ----------

def binomial(n: int, k: int) -> int:
    """Binomial coefficient: n choose k."""
    return math.comb(n, k)


def catalan(n: int) -> int:
    """Return the n-th Catalan number: C_n = (1/(n+1)) * binom(2n, n)."""
    if n < 0:
        raise ValueError("n must be >= 0")
    return math.comb(2 * n, n) // (n + 1)


def factorial(n: int) -> int:
    """Factorial of n."""
    if n < 0:
        raise ValueError("n must be >= 0")
    return math.factorial(n)


# ---------- Binary sequences ----------

def gen_binary_seq(n: int) -> Generator[Tuple[int, ...], None, None]:
    """Generate all binary sequences of length n as tuples of 0/1."""
    if n <= 0:
        yield ()
    else:
        for s in gen_binary_seq(n - 1):
            yield s + (0,)
            yield s + (1,)


def all_binary_sequences(k: int) -> List[Tuple[int, ...]]:
    """Return list of all binary sequences of length k."""
    return list(gen_binary_seq(k))


# ---------- Subdiagonal sequences & permutations ----------

def gen_subdiag(n: int) -> Generator[Tuple[int, ...], None, None]:
    """Generate all subdiagonal sequences of size n."""
    if n <= 0:
        yield ()
    else:
        for prefix in gen_subdiag(n - 1):
            for k in range(1, n + 1):
                yield prefix + (k,)


def seq_to_perm(s: Tuple[int, ...]) -> Tuple[int, ...]:
    """Convert a subdiagonal sequence to a permutation."""
    n = len(s)
    L = list(range(1, n + 1))
    for j in range(n):
        pos = s[j] - 1
        if pos != j:
            L[pos], L[j] = L[j], L[pos]
    return tuple(L)


def gen_permutations(n: int) -> Generator[Tuple[int, ...], None, None]:
    """Generate permutations via subdiagonal sequences (n! items)."""
    for s in gen_subdiag(n):
        yield seq_to_perm(s)


def count_fixed_points(p: Tuple[int, ...]) -> int:
    """Count fixed points in permutation p (where p[i] == i+1)."""
    return sum(1 for i, v in enumerate(p) if v == i + 1)


# ---------- Dyck words ----------

def is_dyck(s: Tuple[int, ...]) -> bool:
    """Check if binary tuple s is a Dyck word (1=open, 0=close)."""
    if len(s) == 0:
        return True
    if s[0] == 0 or s[-1] == 1:
        return False
    
    balance = 0
    for bit in s:
        balance += 1 if bit == 1 else -1
        if balance < 0:
            return False
    
    return balance == 0


def all_dyck_words(n: int) -> List[Tuple[int, ...]]:
    """Return all Dyck words of length 2*n."""
    return [s for s in gen_binary_seq(2 * n) if is_dyck(s)]


def gen_dyck(n: int) -> Generator[Tuple[int, ...], None, None]:
    """Generate Dyck words of length 2*n (filtering binary sequences)."""
    for s in gen_binary_seq(2 * n):
        if is_dyck(s):
            yield s


def gen_dyck_recursive(n: int) -> Generator[Tuple[int, ...], None, None]:
    """Generate Dyck words using recursive decomposition: w = 1 w1 0 w2."""
    if n == 0:
        yield ()
    else:
        for k in range(n):
            for w1 in gen_dyck_recursive(k):
                for w2 in gen_dyck_recursive(n - k - 1):
                    yield (1,) + w1 + (0,) + w2


# ---------- Peaks ----------

def count_peaks(s: Tuple[int, ...]) -> int:
    """Count peaks in sequence s (consecutive 1,0 pairs)."""
    return sum(1 for i in range(len(s) - 1) if s[i] == 1 and s[i + 1] == 0)


def average_peaks(n: int) -> float:
    """Average number of peaks over all Dyck words of length 2*n."""
    if n == 0:
        return 0.0
    mots = all_dyck_words(n)
    total_pics = sum(count_peaks(m) for m in mots)
    return total_pics / catalan(n)


# ---------- Fibonacci words ----------

def gen_fibonacci(n: int) -> Generator[str, None, None]:
    """Generate first n Fibonacci words."""
    s1, s2 = '1', '0'
    for _ in range(n):
        yield s1
        s1, s2 = s2, s2 + s1


# ---------- Examples ----------

if __name__ == "__main__":
    print("\nDyck word validation\n")
    print("(1,0,1,0,1,0,1,0) is Dyck:", is_dyck((1, 0, 1, 0, 1, 0, 1, 0)))
    print("(1,1,1,1,0,0,0,0) is Dyck:", is_dyck((1, 1, 1, 1, 0, 0, 0, 0)))
    print("(1,0,0,1) is Dyck:", is_dyck((1, 0, 0, 1)))
    print("(1,0,1,1,0) is Dyck:", is_dyck((1, 0, 1, 1, 0)))

    print("\nAll Dyck words of length 8 (n=4)\n")
    M = all_dyck_words(4)
    for s in M:
        print(s)

    print("\nPeak counting\n")
    print("(1,0,1,0,1,0,1,0) has", count_peaks((1, 0, 1, 0, 1, 0, 1, 0)), "peaks")
    print("(1,1,0,0) has", count_peaks((1, 1, 0, 0)), "peak")

    print("\nAverage peaks in Dyck words\n")
    print("Average for n=3:", average_peaks(3))
    print("Average for n=5:", average_peaks(5))

    print("\nGenerator example: subdiagonal sequences (n=4)\n")
    n = 4
    it = gen_subdiag(n)
    for _ in range(min(24, factorial(n))):
        print(next(it))

    print("\nGenerator example: permutations (n=4)\n")
    it = gen_permutations(n)
    for _ in range(min(24, factorial(n))):
        print(next(it))

    print("\nFibonacci words: first 8 terms\n")
    n = 8
    it = gen_fibonacci(n)
    for _ in range(n):
        print(next(it))

    print("\nDyck words by filtering (n=3, length 6)\n")
    n = 3
    it = gen_dyck(n)
    for _ in range(catalan(n)):
        print(next(it))

    print("\nDyck words by decomposition (n=3, length 6)\n")
    it = gen_dyck_recursive(n)
    for _ in range(catalan(n)):
        print(next(it))