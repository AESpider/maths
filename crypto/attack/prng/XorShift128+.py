#!/usr/bin/python3
"""
XorShift128+ State Recovery for V8's Math.random()
"""

import z3
import struct

def main():
    # Input sequence - actual observed Math.random() 5 outputs
    sequence = [
        0.9311600617849973,
        0.3551442693830502,
        0.7923158995678377,
        0.787777942408997,
        0.376372264303491,
        # 0.23137147109312428
    ]
    
    # V8 entropy pool is LIFO
    sequence = sequence[::-1]
    
    # Create solver
    solver = z3.Solver()
    
    # Create symbolic states
    se_state0, se_state1 = z3.BitVecs("se_state0 se_state1", 64)
    
    # Build constraints for each output
    for i in range(len(sequence)):
        # XorShift128+ algorithm
        se_s1 = se_state0
        se_s0 = se_state1
        se_state0 = se_s0
        se_s1 ^= se_s1 << 23
        se_s1 ^= z3.LShR(se_s1, 17)
        se_s1 ^= se_s0
        se_s1 ^= z3.LShR(se_s0, 26)
        se_state1 = se_s1
        
        # Extract mantissa from output
        float_64 = struct.pack("d", sequence[i] + 1)
        u_long_long_64 = struct.unpack("<Q", float_64)[0]
        mantissa = u_long_long_64 & ((1 << 52) - 1)
        
        # Add constraint
        solver.add(int(mantissa) == z3.LShR(se_state0, 12))
    
    # Solve
    if solver.check() == z3.sat:
        model = solver.model()
        
        states = {}
        for state in model.decls():
            states[state.__str__()] = model[state]
        
        state0 = states["se_state0"].as_long()
        state1 = states["se_state1"].as_long()
        
        print(f"state0: {state0}")
        print(f"state1: {state1}")
        
        # Generate next value
        u_long_long_64 = (state0 >> 12) | 0x3FF0000000000000
        float_64 = struct.pack("<Q", u_long_long_64)
        next_sequence = struct.unpack("d", float_64)[0]
        next_sequence -= 1
        
        print(f"\nNext value: {next_sequence}")
    else:
        print("Failed to recover state")


if __name__ == "__main__":
    main()