from sage.all import *
import binascii

# Shamir's Secret Sharing malleability
# Modify one share to inject a specific fake secret.

def str_to_int(s):
    return int(binascii.hexlify(s.encode()), 16)

def int_to_str(n):
    try:
        return binascii.unhexlify(hex(n)[2:]).decode()
    except:
        return "Decoding Error"

p = 2**256 - 189
original_msg = "AUTHORIZE_PAYMENT"
target_msg   = "AESpider_WAS_HERE"

secret = str_to_int(original_msg)
fake_secret = str_to_int(target_msg)

# Quorum: 3 participants needed (threshold = 3)
#   1: Alice, 2: Bob, 3: Eve (malicious)
degree = 2 
coeffs = [secret] + [randint(1, p) for _ in range(degree)]
P = PolynomialRing(GF(p), 'x')(coeffs)

# Generate shares
shares = [(i, P(i)) for i in range(1, 4)]
x_alice, y_alice = shares[0]
x_bob, y_bob     = shares[1]
x_eve, y_eve     = shares[2]

print(f"Original Secret: {original_msg}")
print(f"Target Secret  : {target_msg}\n")


# The malleability attack
# Eve wants to find y_forged such that reconstruction yields fake_secret.
# Formula: y' = y + (S' - S) * L(0)^-1

# Calculate Lagrange coefficient for Eve at x=0
# L_eve(0) = product( x_j / (x_j - x_eve) ) for j in {Alice, Bob}
other_x = [x_alice, x_bob]
num = prod([xj for xj in other_x])
den = prod([(xj - x_eve) for xj in other_x])
L_eve = GF(p)(num) / GF(p)(den)

# Compute the forged share
delta_secret = fake_secret - secret
y_eve_forged = GF(p)(y_eve) + GF(p)(delta_secret) / L_eve


# Reconstruction, the system combines shares from Alice, Bob, and Eve (Forged)
corrupted_shares = [
    (x_alice, y_alice),
    (x_bob, y_bob),
    (x_eve, y_eve_forged)
]

# Lagrange interpolation
R = PolynomialRing(GF(p), 'x')
P_rec = R.lagrange_polynomial(corrupted_shares)
recovered_int = P_rec(0)
recovered_msg = int_to_str(Integer(recovered_int))

print(f"Reconstructed  : {recovered_msg}")
print(f"Match ? {recovered_msg == target_msg}")
