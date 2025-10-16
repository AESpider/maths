from sage.all import *
from Crypto.Util.number import *

p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061

# FINITE FIELDS

# [1] Bit length of p
print(f"[1] Bit length: {p.bit_length()}")

# [2] Complete factorization of p-1 (order of F_p*)
F = GF(p)
print(f"[2] Factorization of p-1: {factor(p-1)}")

# [3] Check if element is a generator of F_p
def is_generator(g, p):
    """Check if g generates F_p* using Lagrange's theorem."""
    for f, _ in factor(p-1):
        # If g^((p-1)/f) = 1, then g's order divides (p-1)/f
        if pow(g, (p-1)//f, p) == 1:
            return False
    return True

# Test with a random element
test_element = 2
print(f"[3] Is {test_element} a generator? {is_generator(test_element, p)}")

# ELLIPTIC CURVES

a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134

# Curve over F_p
E = EllipticCurve(GF(p), [a, b])

# [4] Order of the curve over F_p
print(f"[4] Order of E(F_p): {E.order()}")

# [5] Factorization of curve order over F_p^3
E3 = EllipticCurve(GF(p**3, 'x'), [a, b])

# Add p as a known prime factor for faster factorization
pari.addprimes(p)

print(f"[5] Factorization of E(F_p^3) order: {factor(E3.order())}")

# [6] Solve ECDLP: find d such that A = d*G
Gx = 10754634945965100597587232538382698551598951191077578676469959354625325250805353921972302088503050119092675418338771
Ax = 776741307896310549358901148397047715054445374890300753826496778948879054114421829863318830784216542919559209003815

G = E.lift_x(GF(p)(Gx))
A = E.lift_x(GF(p)(Ax))

# Anomalous curve: order equals p, vulnerable to Smart's attack
def smart_attack(P, Q, p):
    """Solve ECDLP on anomalous curves using Smart's attack."""
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p)*p for t in E.a_invariants()])
    
    P_Qp = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_candidate in P_Qp:
        if GF(p)(P_candidate.xy()[1]) == P.xy()[1]:
            P_Qp = P_candidate
            break
            
    Q_Qp = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_candidate in Q_Qp:
        if GF(p)(Q_candidate.xy()[1]) == Q.xy()[1]:
            Q_Qp = Q_candidate
            break
    
    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp
    
    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()
    
    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)
    
    k = phi_Q / phi_P
    return ZZ(k)

d = smart_attack(G, A, p)

assert A == d * G, "Attack failed!"
print(f"[6] Private key d: {d}")