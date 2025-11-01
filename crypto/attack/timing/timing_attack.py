#!/usr/bin/env python3
"""
Timing attack simple example.

Principle:
  - oracle(token) sleeps DELAY_PER_MATCH for every correct character at the
    correct position (creates a timing leak for correct prefixes).
  - attacker tries characters one position at a time, measures average
    response time and picks the character with the largest average delay.

Usage: python3 timing_attack.py
"""

import time

SECRET = "f4k3_f0r_t3st1ng"     # secret to recover (length = 16)
DELAY_PER_MATCH = 0.005         # seconds added per matched character
SAMPLE_ATTEMPTS = 3             # samples per candidate

# Charset attacker will try (ASCII printable characters)
CHARSET = ''.join(chr(i) for i in range(32, 127))

def oracle(token: str) -> None:
    """
    Simulated vulnerable oracle:
      - for each char in token that matches SECRET at same position,
         sleep DELAY_PER_MATCH (adds up for correct prefix).
    Just return after checking.
    """
    for i, ch in enumerate(token):
        if i >= len(SECRET):
            break
        if ch == SECRET[i]:
            # timing leak: longer for correct prefix
            time.sleep(DELAY_PER_MATCH)
    # emulate some minimal processing time beyond sleeps to make timings realistic
    time.sleep(0.001)
    return

# helpers
def measure_avg_latency(trial: str, attempts: int = SAMPLE_ATTEMPTS) -> float:
    """Call oracle(attempt) 'attempts' times and return average elapsed time."""
    timings = []
    for _ in range(attempts):
        t0 = time.perf_counter()
        oracle(trial)
        timings.append(time.perf_counter() - t0)
    # return arithmetic mean
    return sum(timings) / len(timings)

def recover_secret(length: int, verbose: bool = False) -> str:
    """
    Recover the secret of given length. For each position, try every 
    char in CHARSET and pick the char with the maximum average latency.
    """
    recovered = ["?"] * length
    for pos in range(length):
        best_char = None
        best_time = -1.0
        prefix = "".join(recovered[:pos])
        print(f"[*] Guessing position {pos} (known prefix: {prefix})")
        for ch in CHARSET:
            # build trial token: known prefix + candidate + padd
            padd = "A" * (length - pos - 1)
            trial = prefix + ch + padd
            avg = measure_avg_latency(trial)
            if verbose : print(f"    try '{ch}': avg {avg:.4f}s")
            # select the candidate with the largest average delay
            if avg > best_time:
                best_time = avg
                best_char = ch
        recovered[pos] = best_char
        print(f"[+] Position {pos} -> '{best_char}' (avg {best_time:.4f}s)\n")
    return "".join(recovered)


if __name__ == "__main__":
    print("Lauching timing attack..")

    # determine secret length
    secret_lenght = len(SECRET)
    print(f"Secret length: {secret_lenght}\n")

    guessed = recover_secret(secret_lenght, verbose=False)
    
    # show results
    print(f"Recovered (best guess): {guessed}")
    print("Match ?", SECRET == guessed)
