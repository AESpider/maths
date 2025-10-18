"""
Correlation attack on the Geffe generator stream cipher.
The Geffe generator combines 3 LFSRs using: z = x3 ^ (x2 & x3) ^ (x1 & x2)
This creates 75% correlation with LFSR1 and LFSR3, enabling a reduction in 
the search space.
"""

import time

# Observed keystream (100 bits)
KEYSTREAM = [
    0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0,
    0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 0, 0, 1, 0
]

# LFSR parameters
L1, L2, L3 = 13, 11, 9
TAPS1 = [1, 3, 4, 13]  # P1(x) = 1 + x + x^3 + x^4 + x^13
TAPS2 = [2, 11]        # P2(x) = 1 + x^2 + x^11
TAPS3 = [4, 9]         # P3(x) = 1 + x^4 + x^9


def lfsr_step(state, taps):
    """Advance LFSR by one step. Returns (output_bit, new_state)."""
    output = state[0]
    feedback = sum(state[-tap] for tap in taps) % 2
    return output, state[1:] + [feedback]


def generate_sequence(initial_state, taps, length):
    """Generate LFSR sequence of given length."""
    state = initial_state[:]
    sequence = []
    for _ in range(length):
        bit, state = lfsr_step(state, taps)
        sequence.append(bit)
    return sequence


def int_to_state(value, length):
    """Convert integer to LFSR state (MSB first)."""
    return [(value >> i) & 1 for i in range(length - 1, -1, -1)]


def geffe_combine(s1, s2, s3):
    """Geffe combining function: z = s3 ^ (s2 & s3) ^ (s1 & s2)."""
    return s3 ^ (s2 & s3) ^ (s1 & s2)


def find_correlated_lfsr(length, taps, keystream):
    """Brute force LFSR states, return best match based on correlation."""
    best_state_val = None
    best_sequence = None
    max_matches = 0
    
    for state_val in range(2**length):
        state = int_to_state(state_val, length)
        sequence = generate_sequence(state, taps, len(keystream))
        
        # Count matching bits (correlation metric)
        matches = sum(1 for i in range(len(keystream)) if sequence[i] == keystream[i])
        
        if matches > max_matches:
            max_matches = matches
            best_state_val = state_val
            best_sequence = sequence
    
    return best_state_val, best_sequence, max_matches


def find_middle_lfsr(s1_seq, s3_seq, keystream, taps):
    """Find LFSR2 by testing all states against known LFSR1 and LFSR3."""
    for s2_val in range(2**L2):
        s2_state = int_to_state(s2_val, L2)
        s2_seq = generate_sequence(s2_state, taps, len(keystream))
        
        # Verify if combination produces observed keystream
        if all(geffe_combine(s1_seq[i], s2_seq[i], s3_seq[i]) == keystream[i] 
               for i in range(len(keystream))):
            return s2_val, s2_state
    
    return None, None


def correlation_attack():
    """Execute correlation attack on Geffe generator."""
    print(f"Observed keystream length: {len(KEYSTREAM)} bits\n")
    
    # Step 1: Attack LFSR1
    print("[1] Attacking LFSR1...")
    t1 = time.time()
    s1_val, s1_seq, s1_matches = find_correlated_lfsr(L1, TAPS1, KEYSTREAM)
    t1 = time.time() - t1
    
    print(f"    Best candidate: {s1_val}")
    print(f"    Correlation: {s1_matches}/{len(KEYSTREAM)} = {s1_matches/len(KEYSTREAM):.2f}")
    print(f"    Time: {t1:.3f}s\n")
    
    # Step 2: Attack LFSR3
    print("[2] Attacking LFSR3...")
    t3 = time.time()
    s3_val, s3_seq, s3_matches = find_correlated_lfsr(L3, TAPS3, KEYSTREAM)
    t3 = time.time() - t3
    
    print(f"    Best candidate: {s3_val}")
    print(f"    Correlation: {s3_matches}/{len(KEYSTREAM)} = {s3_matches/len(KEYSTREAM):.2f}")
    print(f"    Time: {t3:.3f}s\n")
    
    # Step 3: Attack LFSR2 (using known LFSR1 and LFSR3)
    print("[3] Attacking LFSR2...")
    t2 = time.time()
    s2_val, s2_state = find_middle_lfsr(s1_seq, s3_seq, KEYSTREAM, TAPS2)
    t2 = time.time() - t2
    
    if s2_val is not None:
        print(f"    SOLUTION FOUND!")
        print(f"    LFSR1 initial state: {s1_val} -> {int_to_state(s1_val, L1)}")
        print(f"    LFSR2 initial state: {s2_val} -> {s2_state}")
        print(f"    LFSR3 initial state: {s3_val} -> {int_to_state(s3_val, L3)}")
    else:
        print(f"    No solution found")
    
    print(f"    Time: {t2:.3f}s\n")
    
    # Complexity analysis
    total_time = t1 + t2 + t3
    brute_force = 2**(L1 + L2 + L3)
    correlation_attack = 2**L1 + 2**L2 + 2**L3
    speedup = brute_force // correlation_attack
    
    print(f"Total time: {total_time}s\n")

    print("Complexity Analysis")
    print(f"Brute force:        2^{L1+L2+L3} = {brute_force:,}")
    print(f"Correlation attack: 2^{L1} + 2^{L2} + 2^{L3} = {correlation_attack:,}")
    print(f"Speedup factor:     {speedup:,}")


if __name__ == "__main__":
    correlation_attack()