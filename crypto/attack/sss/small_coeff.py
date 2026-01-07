from sage.all import *

# Shamir's Secret Sharing with small coefficients
# Use differences to eliminate the secret, then LLL to find small coeffs.

p = 2**256 - 189 
degree = 10     
secret = 13377331 

# Weakness: coefficients are very small (<< p)
coeffs = [secret] + [randint(1, 1000) for _ in range(degree)]
P = PolynomialRing(ZZ, 'x')(coeffs)

# Under-determined: we use 8 shares (need 11 normally)
num_shares = degree - 2 
shares = [(i, P(i) % p) for i in range(1, num_shares + 1)]

print(f"Secret: {secret}")
print(f"Available Shares: {num_shares}")

# Lattice attack, we eliminate the secret (a0) by taking differences.
# Target: find small coefficients a1..ad.
x0, y0 = shares[0]
diff_shares = []

for i in range(1, num_shares):
    xi, yi = shares[i]
    dy = (yi - y0) % p
    # row for powers: (xi^j - x0^j)
    dx_powers = [(xi**j - x0**j) % p for j in range(1, degree + 1)]
    diff_shares.append((dx_powers, dy))

# Linear algebra setup: M * A = Y mod p
dim = degree 
M_rows = [s[0] for s in diff_shares]
Y_vals = [s[1] for s in diff_shares]

M_mat = Matrix(GF(p), M_rows)
Y_vec = vector(GF(p), Y_vals)

# Build Lattice, find particular solution and kernel
part_sol = M_mat.solve_right(Y_vec).change_ring(ZZ)
kernel = M_mat.right_kernel().basis()

# Lattice rows: kernel + p*Identity + Particular_Solution
L = Matrix(ZZ, len(kernel) + dim + 1, dim + 1)

# Add kernel
for i, k in enumerate(kernel):
    for j in range(dim): 
        L[i, j] = k[j]

# Add modulo p
offset = len(kernel)
for i in range(dim):
    L[offset + i, i] = p

# Add particular solution (embedded)
row_tgt = offset + dim
for j in range(dim): 
        L[row_tgt, j] = part_sol[j]
L[row_tgt, dim] = 1

print("\nRunning LLL reduction...")
L_red = L.LLL()

recovered_secret = None
for row in L_red:
    if abs(row[dim]) == 1:
        # we found the small coefficients a1..ad
        coeffs_found = row[:dim]
        if row[dim] == -1: 
            coeffs_found = -coeffs_found
        
        # reconstruct S = y0 - sum(aj * x0^j) -> use ** for python power
        sum_val = sum(coeffs_found[j-1] * (x0**j) for j in range(1, dim + 1))
        recovered_secret = (y0 - sum_val) % p
        break

print(f"Recovered Secret: {recovered_secret}")
print(f"Match ? {recovered_secret == secret}")
