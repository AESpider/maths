#!/usr/bin/env python3
"""
Simulation & sampling for probability distributions.
Dice, Bernoulli, binomial, geometric, Poisson.
"""

from collections import Counter
import random
import math
import sys
from typing import Callable, Dict, Iterable, Any

if sys.version_info[0] < 3:
    raise RuntimeError("This script requires Python 3.")

# ---------- Math helpers ----------

def frac(x: float) -> float:
    """Fractional part of x in [0,1)."""
    return x - math.floor(x)


def factorial(n: int) -> int:
    """Factorial of n."""
    if n < 0:
        raise ValueError("n must be >= 0")
    f = 1
    for i in range(2, n + 1):
        f *= i
    return f


def binomial_coeff(n: int, k: int) -> int:
    """Binomial coefficient C(n,k)."""
    if not (isinstance(n, int) and isinstance(k, int)):
        raise TypeError("n and k must be integers")
    if k < 0 or k > n:
        raise ValueError("k must satisfy 0 <= k <= n")
    return factorial(n) // (factorial(k) * factorial(n - k))


def tv_distance(d1: Dict[Any, float], d2: Dict[Any, float]) -> float:
    """Total variation distance between two distributions in [0,1]."""
    all_keys = set(d1) | set(d2)
    s = 0.0
    for key in all_keys:
        s += abs(d1.get(key, 0.0) - d2.get(key, 0.0))
    return s / 2.0


# ---------- Basic dice simulators ----------

def roll_die6() -> int:
    """Roll a fair 6-sided die (1..6)."""
    return random.randint(1, 6)


def empirical_frequencies(sim: Callable[[], Any], n: int) -> Dict[Any, float]:
    """Return empirical frequencies of simulator sim() after n trials."""
    if n <= 0:
        return {}
    counts = Counter(sim() for _ in range(n))
    return {k: v / n for k, v in counts.items()}


def print_distribution(d: Dict[Any, float]) -> None:
    """Print distribution sorted by key."""
    for k in sorted(d.keys(), key=lambda x: str(x)):
        print(f"{k}: {d[k]:.6f}")


# ---------- Utilities ----------

def simulate_first_six() -> int:
    """Return number of rolls until first 6 (including the successful roll)."""
    rolls = 0
    while True:
        rolls += 1
        if roll_die6() == 6:
            return rolls


# ---------- Generator factories ----------

def make_die(faces: int) -> Callable[[], int]:
    """Return a simulator for a fair die with 'faces' faces (1..faces)."""
    if not isinstance(faces, int) or faces < 1:
        raise ValueError("faces must be an integer >= 1")
    
    def sim() -> int:
        return random.randint(1, faces)
    
    return sim


def make_bernoulli(p: float) -> Callable[[], int]:
    """Bernoulli(p) returning 1 for success, 0 for failure."""
    if not (0.0 <= p <= 1.0):
        raise ValueError("p must be in [0,1]")
    
    def sim() -> int:
        return 1 if random.random() < p else 0
    
    return sim


def make_sum(sim1: Callable[[], int], sim2: Callable[[], int]) -> Callable[[], int]:
    """Return simulator that sums two simulators (sim1() + sim2())."""
    def sim() -> int:
        return sim1() + sim2()
    
    return sim


def make_sum_list(sims: Iterable[Callable[[], int]]) -> Callable[[], int]:
    """Return simulator that sums an iterable of simulators."""
    sims_list = list(sims)
    
    def sim() -> int:
        return sum(s() for s in sims_list)
    
    return sim


def make_binomial(n: int, p: float) -> Callable[[], int]:
    """Binomial(n,p) by summing n Bernoulli(p) trials."""
    if not isinstance(n, int) or n < 0:
        raise ValueError("n must be an integer >= 0")
    bern = make_bernoulli(p)
    
    def sim() -> int:
        return sum(bern() for _ in range(n))
    
    return sim


def make_geometric(p: float) -> Callable[[], int]:
    """Geometric(p): number of trials until first success (1,2,...)."""
    if not (0.0 < p <= 1.0):
        raise ValueError("p must be in (0,1]")
    
    def sim() -> int:
        trials = 1
        while random.random() >= p:
            trials += 1
        return trials
    
    return sim


def make_poisson(lmbda: float) -> Callable[[], int]:
    """Poisson(lambda) using Knuth's algorithm."""
    if lmbda < 0.0:
        raise ValueError("lambda must be >= 0")
    
    def sim() -> int:
        if lmbda == 0:
            return 0
        L = math.exp(-lmbda)
        k = 0
        p = 1.0
        while p > L:
            k += 1
            p *= random.random()
        return k - 1
    
    return sim


def make_from_distribution(d: Dict[Any, float]) -> Callable[[], Any]:
    """Create a sampler from a discrete distribution {value: prob}."""
    if not d:
        raise ValueError("distribution dictionary must be non-empty")
    
    items = list(d.items())
    values, probs = zip(*items)
    
    for p in probs:
        if p < 0:
            raise ValueError("probabilities must be non-negative")
    
    # Build cumulative distribution
    cum = []
    s = 0.0
    for p in probs:
        s += p
        cum.append(s)
    
    total = cum[-1]
    if total <= 0.0:
        raise ValueError("sum of probabilities must be > 0")
    
    cum = [c / total for c in cum]

    def sim():
        u = random.random()
        for val, c in zip(values, cum):
            if u <= c:
                return val
        return values[-1]
    
    return sim


# ---------- Examples ----------

if __name__ == "__main__":
    print("Empirical freq for a 6-sided die (n=100,000):")
    dist = empirical_frequencies(roll_die6, 100_000)
    print_distribution(dist)
    print()

    print("First-six distribution (n=100,000):")
    dist_first6 = empirical_frequencies(simulate_first_six, 100_000)
    print_distribution(dist_first6)
    print()

    print("Sum of two 6-sided dice (10 samples):")
    d6 = make_die(6)
    sum_sim = make_sum(d6, d6)
    samples = [sum_sim() for _ in range(10)]
    print(samples)
    print()

    print("Binomial(5,0.5) samples:", [make_binomial(5, 0.5)() for _ in range(10)])
    print("Geometric(0.2) samples:", [make_geometric(0.2)() for _ in range(10)])
    print("Poisson(1) samples:", [make_poisson(1.0)() for _ in range(10)])