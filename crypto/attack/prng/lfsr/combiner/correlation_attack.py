"""
Correlation attack on a 4-LFSR combiner with function:
f(x1,x2,x3,x4) = x1 + x3 + x2(x1 + x4)

Exploits correlations:
- P[f = x1 + x3] = 0.75 (bias +0.25)
- P[f = x3 + x4] = 0.75 (bias +0.25)
"""

import time
import random

# LFSR parameters (primitive polynomials)
TAPS1 = [2, 5]; L1 = 5     # x^5 + x^2 + 1
TAPS2 = [4, 9]; L2 = 9     # x^9 + x^4 + 1
TAPS3 = [1, 7]; L3 = 7     # x^7 + x + 1
TAPS4 = [2, 11]; L4 = 11   # x^11 + x^2 + 1

KEYSTREAM_LENGTH = 100  # bits to generate/attack


def int_to_state(value, length):
    """Convert integer to LFSR state (LSB first)."""
    return [(value >> i) & 1 for i in range(length)]


def lfsr_step(state, taps):
    """Advance LFSR by one step. Returns (new_state, output_bit)."""
    feedback = sum(state[tap - 1] for tap in taps) % 2
    new_state = [feedback] + state[:-1]
    output = state[-1]
    return new_state, output


def generate_sequence(initial_state, taps, length):
    """Generate LFSR output sequence of given length."""
    state = initial_state[:]
    sequence = []
    for _ in range(length):
        state, output = lfsr_step(state, taps)
        sequence.append(output)
    return sequence


def combining_function(x1, x2, x3, x4):
    """Combiner: f(x1,x2,x3,x4) = x1 + x3 + x2(x1 + x4)."""
    return x1 ^ x3 ^ (x2 & (x1 ^ x4))


def generate_keystream(k1, k2, k3, k4, length):
    """Generate combined keystream from 4 LFSRs."""
    seq1 = generate_sequence(int_to_state(k1, L1), TAPS1, length)
    seq2 = generate_sequence(int_to_state(k2, L2), TAPS2, length)
    seq3 = generate_sequence(int_to_state(k3, L3), TAPS3, length)
    seq4 = generate_sequence(int_to_state(k4, L4), TAPS4, length)
    
    return [combining_function(seq1[i], seq2[i], seq3[i], seq4[i]) 
            for i in range(length)]


def precompute_sequences(length):
    """Precompute all possible LFSR sequences for efficiency."""
    print("Precomputing LFSR sequences...")
    seqs = [{}, {}, {}, {}]
    
    for k1 in range(1, 2**L1):
        seqs[0][k1] = generate_sequence(int_to_state(k1, L1), TAPS1, length)
    for k2 in range(1, 2**L2):
        seqs[1][k2] = generate_sequence(int_to_state(k2, L2), TAPS2, length)
    for k3 in range(1, 2**L3):
        seqs[2][k3] = generate_sequence(int_to_state(k3, L3), TAPS3, length)
    for k4 in range(1, 2**L4):
        seqs[3][k4] = generate_sequence(int_to_state(k4, L4), TAPS4, length)
    
    return seqs


def correlation_attack(keystream, sequences):
    """Execute multi-phase correlation attack."""
    
    # Phase 1: Exploit P[f = x1 + x3] = 0.75
    print("\n[Phase 1] Attacking via x1 + x3 correlation")
    t1 = time.time()
    
    candidates_k1_k3 = []
    for k1 in range(1, 2**L1):
        seq1 = sequences[0][k1]
        for k3 in range(1, 2**L3):
            seq3 = sequences[2][k3]
            
            # Test x1 + x3 correlation
            matches = sum(1 for i in range(len(keystream)) 
                         if (seq1[i] ^ seq3[i]) == keystream[i])
            score = matches / len(keystream)
            
            if score >= 0.65:  # Threshold based on 0.75 correlation
                candidates_k1_k3.append((k1, k3, score))
    
    t1 = time.time() - t1
    print(f"    Found {len(candidates_k1_k3)} candidates (k1, k3)")
    
    if not candidates_k1_k3:
        print("    No candidates found - try increasing keystream length")
        return [], 0
    print(f"    Best score: {max(c[2] for c in candidates_k1_k3):.3f}")
    print(f"    Time: {t1:.3f}s")
    
    # Phase 2: Exploit P[f = x3 + x4] = 0.75
    print("\n[Phase 2] Attacking via x3 + x4 correlation")
    t2 = time.time()
    
    candidates_k1_k3_k4 = []
    for k1, k3, _ in candidates_k1_k3:
        seq3 = sequences[2][k3]
        
        for k4 in range(1, 2**L4):
            seq4 = sequences[3][k4]
            
            # Test x3 + x4 correlation
            matches = sum(1 for i in range(len(keystream)) 
                         if (seq3[i] ^ seq4[i]) == keystream[i])
            score = matches / len(keystream)
            
            if score >= 0.65:
                candidates_k1_k3_k4.append((k1, k3, k4, score))
    
    t2 = time.time() - t2
    print(f"    Found {len(candidates_k1_k3_k4)} candidates (k1, k3, k4)")
    if candidates_k1_k3_k4:
        print(f"    Best score: {max(c[3] for c in candidates_k1_k3_k4):.3f}")
    print(f"    Time: {t2:.3f}s")
    
    # Phase 3: Brute force k2 with known k1, k3, k4
    print("\n[Phase 3] Brute forcing k2")
    t3 = time.time()
    
    solutions = []
    for k1, k3, k4, _ in candidates_k1_k3_k4:
        seq1 = sequences[0][k1]
        seq3 = sequences[2][k3]
        seq4 = sequences[3][k4]
        
        for k2 in range(1, 2**L2):
            seq2 = sequences[1][k2]
            
            # Test complete combining function
            matches = sum(1 for i in range(len(keystream))
                         if combining_function(seq1[i], seq2[i], seq3[i], seq4[i]) 
                         == keystream[i])
            
            score = matches / len(keystream)
            if score > 0.99:  # Near-perfect match
                solutions.append((k1, k2, k3, k4))
    
    t3 = time.time() - t3
    print(f"    Found {len(solutions)} solution")
    print(f"    Time: {t3:.3f}s\n")

    print(f"Attack finished in {t1+t2+t3:.2f} seconds.\n")

    return solutions


def main():
    print("4-LFSR Combiner Correlation Attack\n")
    
    # Generate random initial states (non-zero)
    true_k1 = random.randint(1, 2**L1 - 1)
    true_k2 = random.randint(1, 2**L2 - 1)
    true_k3 = random.randint(1, 2**L3 - 1)
    true_k4 = random.randint(1, 2**L4 - 1)
    
    print("True initial states (hidden from attacker):")
    print(f"  k1 = {true_k1} = {int_to_state(true_k1, L1)}")
    print(f"  k2 = {true_k2} = {int_to_state(true_k2, L2)}")
    print(f"  k3 = {true_k3} = {int_to_state(true_k3, L3)}")
    print(f"  k4 = {true_k4} = {int_to_state(true_k4, L4)}")
    
    # Generate observed keystream
    print(f"\nGenerating {KEYSTREAM_LENGTH}-bit keystream...")
    keystream = generate_keystream(true_k1, true_k2, true_k3, true_k4, KEYSTREAM_LENGTH)

    # Display the start of the keystream (max 32 bits)
    keystream_display = ''.join(map(str, keystream[:min(32, len(keystream))]))
    if len(keystream) > 32:
        keystream_display += "..."
    print(f"Observed keystream: {keystream_display}\n")
    
    # Precompute sequences
    sequences = precompute_sequences(KEYSTREAM_LENGTH)
    
    # Execute attack
    solutions = correlation_attack(keystream, sequences)

    # Display results
    if solutions:
        for i, (k1, k2, k3, k4) in enumerate(solutions):
            print(f"Solution {i+1}:")
            print(f"  k1 = {k1} = {int_to_state(k1, L1)}")
            print(f"  k2 = {k2} = {int_to_state(k2, L2)}")
            print(f"  k3 = {k3} = {int_to_state(k3, L3)}")
            print(f"  k4 = {k4} = {int_to_state(k4, L4)}")
            
            # Verify correctness
            if k1 == true_k1 and k2 == true_k2 and k3 == true_k3 and k4 == true_k4:
                print("Correct solution found!")
            else: print()
    else:
        print("No solution found")

if __name__ == "__main__":
    main()