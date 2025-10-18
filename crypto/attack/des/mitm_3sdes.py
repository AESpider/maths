#!/usr/bin/env python3
"""
Attack MITM for 3-SDES (EDE)
Usage: python3 mitm_3sdes.py
"""

# --- SDES primitives ---
P10 = [3,5,2,7,4,10,1,9,8,6]
P8  = [6,3,7,4,8,5,10,9]
IP  = [2,6,3,1,4,8,5,7]
IP_INV = [4,1,3,5,7,2,8,6]
EP  = [4,1,2,3,2,3,4,1]
P4  = [2,4,3,1]

S0 = [
    [1,0,3,2],
    [3,2,1,0],
    [0,2,1,3],
    [3,1,3,2]
]
S1 = [
    [0,1,2,3],
    [2,0,1,3],
    [3,0,1,0],
    [2,1,0,3]
]

def int_to_bits(x,n):
    return [(x >> (n-1-i)) & 1 for i in range(n)]

def bits_to_int(bits):
    x = 0
    for b in bits:
        x = (x<<1) | (b&1)
    return x

def permute(bits, table):
    return [ bits[i-1] for i in table ]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_subkeys(key10):
    b = int_to_bits(key10, 10)
    p10 = permute(b, P10)
    L, R = p10[:5], p10[5:]
    L1, R1 = left_shift(L,1), left_shift(R,1)
    K1 = bits_to_int(permute(L1+R1, P8))
    L2, R2 = left_shift(L1,2), left_shift(R1,2)
    K2 = bits_to_int(permute(L2+R2, P8))
    return K1, K2

def fk(bits8, subkey8):
    L, R = bits8[:4], bits8[4:]
    ep = permute(R, EP)
    sb = int_to_bits(subkey8, 8)
    x = [a^b for a,b in zip(ep, sb)]
    l4, r4 = x[:4], x[4:]
    row = (l4[0]<<1) | l4[3]; col = (l4[1]<<1) | l4[2]
    s0 = int_to_bits(S0[row][col], 2)
    row = (r4[0]<<1) | r4[3]; col = (r4[1]<<1) | r4[2]
    s1 = int_to_bits(S1[row][col], 2)
    p4 = permute(s0 + s1, P4)
    newL = [a^b for a,b in zip(L, p4)]
    return newL + R

def sdes_encrypt_block(plain8_int, key10_int):
    K1, K2 = generate_subkeys(key10_int)
    bits = int_to_bits(plain8_int, 8)
    x = permute(bits, IP)
    x = fk(x, K1)
    x = x[4:] + x[:4]   # swap
    x = fk(x, K2)
    c = permute(x, IP_INV)
    return bits_to_int(c)

def sdes_decrypt_block(cipher8_int, key10_int):
    K1, K2 = generate_subkeys(key10_int)
    bits = int_to_bits(cipher8_int, 8)
    x = permute(bits, IP)
    x = fk(x, K2)
    x = x[4:] + x[:4]
    x = fk(x, K1)
    p = permute(x, IP_INV)
    return bits_to_int(p)

# -------- 3-SDES (EDE) --------
def triple_encrypt_EDE(plain8, k1,k2,k3):
    t1 = sdes_encrypt_block(plain8, k1)
    t2 = sdes_decrypt_block(t1, k2)
    t3 = sdes_encrypt_block(t2, k3)
    return t3

# ------------- Data  -------------

PC = [([0,0,1,1,1,1,0,1],[0,0,1,0,1,1,0,1]),
      ([0,0,0,0,1,1,0,1],[0,0,1,1,1,0,1,0]),
      ([0,0,0,1,0,0,1,0],[1,1,0,1,1,0,1,1]),
      ([1,1,0,1,0,1,1,0],[0,0,1,1,0,0,1,1]),
      ([0,1,0,0,0,0,1,1],[0,1,1,1,1,1,0,1]),
      ([0,0,0,1,0,0,0,0],[0,0,0,1,0,1,0,1]),
      ([0,1,0,0,1,0,1,0],[0,0,0,0,0,1,1,1]),
      ([0,1,0,1,0,0,0,1],[0,0,1,1,1,0,0,0]),
      ([1,1,1,1,0,0,1,0],[1,1,1,0,0,0,1,0]),
      ([0,0,0,0,1,0,1,1],[1,0,1,0,0,1,1,0])]

pairs = [(bits_to_int(p), bits_to_int(c)) for p,c in PC]

# ------------------------- Attack MITM -------------------------

# 1. Build table_left: for each k1 -> tuple( E_k1(P_i) )
# 2. Build table_right: for each k3 -> tuple( D_k3(C_i) )
# 3. For each k2: precompute D_k2[x] for x in 0..255, then transform each left-tuple and lookup in table_right. 
# 
# Candidates are (k1,k2,k3). Verify on all pairs.
# Complexity: O(2^10 * 256 + 2^10 * 10) encryptions.

# 1. left table
left = {}   # tuple -> list of k1
for k1 in range(1024):
    t = tuple(sdes_encrypt_block(P, k1) for P,_ in pairs)
    left.setdefault(t, []).append(k1)

# 2. right table
right = {}  # tuple -> list of k3
for k3 in range(1024):
    t = tuple(sdes_decrypt_block(C, k3) for _,C in pairs)
    right.setdefault(t, []).append(k3)

# 3. try each k2
candidates = []
for k2 in range(1024):
    Dk2 = [ sdes_decrypt_block(x, k2) for x in range(256) ]
    # transform each left-tuple via Dk2 and check equality with some right-tuple
    for t_left, k1_list in left.items():
        transformed = tuple(Dk2[v] for v in t_left)
        if transformed in right:
            for k1 in k1_list:
                for k3 in right[transformed]:
                    candidates.append((k1,k2,k3))

# Final verification (should be few)
valid = []
for (k1,k2,k3) in candidates:
    ok = True
    for P,C in pairs:
        if triple_encrypt_EDE(P, k1,k2,k3) != C:
            ok = False; break
    if ok:
        valid.append((k1,k2,k3))

if not valid:
    print("No valid triple found.")
else:
    print("Valid triples (K1, K2, K3):")
    for k1,k2,k3 in valid:
        print(f" K1={k1:03d} (bin {k1:010b}), K2={k2:03d} (bin {k2:010b}), K3={k3:03d} (bin {k3:010b})")
