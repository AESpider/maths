"""
Correlation analysis of the combining function:
f(x1,x2,x3,x4) = x1*x2 + x1 + x2*x4 + x3 = x1 + x3 + x2(x1 + x4)

Analyzes balance, correlations with linear functions, and Walsh-Hadamard transform.
"""

from itertools import product

N = 4
TOTAL = 2**N  # 16 possible inputs


def combining_function(x1, x2, x3, x4):
    """Combiner: f(x1,x2,x3,x4) = x1 + x3 + x2(x1 + x4)"""
    return x1 ^ x3 ^ (x2 & (x1 ^ x4))


def all_inputs():
    """Generate all possible 4-bit inputs."""
    return list(product([0, 1], repeat=N))


def analyze_balance():
    """Check if function is balanced (equal 0s and 1s)."""
    count_0 = count_1 = 0
    
    for x in all_inputs():
        if combining_function(*x) == 0:
            count_0 += 1
        else:
            count_1 += 1
    
    print(f"\nDistribution: {count_0} zeros, {count_1} ones")
    
    if count_0 == count_1:
        print("Function is balanced")
    else:
        bias = (count_0 - count_1) / TOTAL
        print(f"Function is unbalanced (bias: {bias})")
    
    print("\n" + "-" * 50)


def analyze_correlations():
    """Find correlations with all linear combinations."""
    
    linear_combinations = []
    
    # Individual variables: x1, x2, x3, x4
    for i in range(N):
        name = f"x{i+1}"
        func = lambda bits, idx=i: bits[idx]
        linear_combinations.append((name, func))
    
    # Pairs: x1+x2, x1+x3, etc.
    for i in range(N):
        for j in range(i + 1, N):
            name = f"x{i+1} + x{j+1}"
            func = lambda bits, i1=i, i2=j: bits[i1] ^ bits[i2]
            linear_combinations.append((name, func))
    
    # Triples: x1+x2+x3, etc.
    for i in range(N):
        for j in range(i + 1, N):
            for k in range(j + 1, N):
                name = f"x{i+1} + x{j+1} + x{k+1}"
                func = lambda bits, i1=i, i2=j, i3=k: bits[i1] ^ bits[i2] ^ bits[i3]
                linear_combinations.append((name, func))
    
    # All four: x1+x2+x3+x4
    name = "x1 + x2 + x3 + x4"
    func = lambda bits: bits[0] ^ bits[1] ^ bits[2] ^ bits[3]
    linear_combinations.append((name, func))
    
    print("Correlations found:")
    
    for name, func in linear_combinations:
        matches = sum(1 for x in all_inputs() if combining_function(*x) == func(x))
        probability = matches / TOTAL
        
        if probability != 0.5:  # Non-trivial correlation
            bias = probability - 0.5
            print(f"  P[f = {name}] = {matches}/{TOTAL} = {probability:.2f} (bias: {bias:+.2f})")
    
    print("\n" + "-" * 50)


def correlation_matrix():
    """Compute correlation matrix between all variables and f."""
    
    variables = ["x1", "x2", "x3", "x4", "f"]
    inputs = all_inputs()
    
    # Generate sequences for each variable
    sequences = {
        "x1": [x[0] for x in inputs],
        "x2": [x[1] for x in inputs],
        "x3": [x[2] for x in inputs],
        "x4": [x[3] for x in inputs],
        "f":  [combining_function(*x) for x in inputs]
    }
    
    print("Correlation matrix P[A = B]:\n")
    print("     ", end="")
    for var in variables:
        print(f"{var:>6}", end="")
    print()
    
    for var1 in variables:
        print(f"{var1:<5}", end="")
        for var2 in variables:
            matches = sum(1 for i in range(TOTAL) 
                         if sequences[var1][i] == sequences[var2][i])
            prob = matches / TOTAL
            print(f"{prob:6.3f}", end="")
        print()
    
    print("\n" + "-" * 50)


def walsh_hadamard_transform():
    """Compute Walsh-Hadamard transform coefficients."""
    
    inputs = all_inputs()
    
    # Boolean function as vector: {0,1} → {+1,-1}
    f_vector = [(-1) ** combining_function(*x) for x in inputs]
    
    print("Walsh-Hadamard Transform:\n")
    print(f"f vector: {f_vector}\n")
    
    # Compute Walsh coefficients for key linear functions
    linear_functions = [
        ("x1 + x3", lambda x1, x2, x3, x4: x1 ^ x3),
        ("x3 + x4", lambda x1, x2, x3, x4: x3 ^ x4),
        ("x1 + x2 + x3", lambda x1, x2, x3, x4: x1 ^ x2 ^ x3),
        ("x2 + x3 + x4", lambda x1, x2, x3, x4: x2 ^ x3 ^ x4),
    ]
    
    for name, lin_func in linear_functions:
        walsh_coeff = sum(f_vector[i] * ((-1) ** lin_func(*inputs[i])) 
                         for i in range(TOTAL))
        correlation = walsh_coeff / TOTAL
        print(f"  Walsh({name}) = {walsh_coeff}  ->  correlation = {correlation:+.2f}")
    
    print("\n" + "-" * 50)


def main():
    print("Correlation Analysis of Combining Function\n")
    print("f(x1,x2,x3,x4) = x1*x2 + x1 + x2*x4 + x3")
    print("               = x1 + x3 + x2(x1 + x4)")
    
    analyze_balance()
    analyze_correlations()
    correlation_matrix()
    walsh_hadamard_transform()


if __name__ == "__main__":
    main()