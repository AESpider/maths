#!/usr/bin/env python3
"""
Smart's Attack on Anomalous Elliptic Curves
Paper: Weak Curves In Elliptic Curve Cryptography
https://wstein.org/edu/2010/414/projects/novotney.pdf
"""

from sage.all import *

def lift_point(P, p, prec):
    """
    Lift a point from F_p to Q_p using Hensel's lemma.
    
    Args:
        P: Point on elliptic curve over F_p
        p: Prime modulus
        prec: p-adic precision
    
    Returns:
        Lifted point in Q_p
    """
    E = P.curve()
    Eq = E.change_ring(QQ)
    Eqp = Eq.change_ring(Qp(p, prec))
    
    x_P, y_P = map(ZZ, P.xy())
    
    # Build Weierstrass equation: g(y) = y^2 + a1*x*y + a3*y - x^3 - a2*x^2 - a4*x - a6
    y = var('y')
    g = (y**2 
         + Eq.a1()*x_P*y + Eq.a3()*y 
         - x_P**3 - Eq.a2()*x_P**2 - Eq.a4()*x_P - Eq.a6())
    g_prime = diff(g, y)
    
    # Hensel lifting via Newton iterations
    y_lift = y_P
    for i in range(1, prec):
        g_val = Integer(g.subs(y=y_lift))
        g_prime_val = Integer(g_prime.subs(y=y_lift))
        
        if gcd(g_prime_val, p) != 1:
            raise ValueError(f"Hensel lift failed: derivative not invertible at step {i}")
        
        # Newton: y := y - g(y)/g'(y) mod p^(i+1)
        y_lift = ZZ(Mod(y_lift - inverse_mod(g_prime_val, p**i) * g_val, p**(i+1)))
    
    return Eqp(Eqp.base_ring()(x_P), Eqp.base_ring()(y_lift))


def smart_attack(P, Q, p, prec=8):
    """
    Solve ECDLP on anomalous curves using Smart's attack.
    
    The attack exploits the p-adic elliptic logarithm on curves with trace of 
    Frobenius = 1 (i.e., #E(F_p) = p).
    
    Args:
        P: Base point
        Q: Target point (find k where Q = k*P)
        p: Prime (must equal curve order)
        prec: p-adic precision (default: 8)
    
    Returns:
        Discrete logarithm k such that Q = k*P
    """
    # Lift points to p-adic field
    P_lifted = lift_point(P, p, prec)
    Q_lifted = lift_point(Q, p, prec)
    
    # Compute p-adic elliptic logarithm: phi(P) = -x(pP) / y(pP)
    x_pP, y_pP = (p * P_lifted).xy()
    x_pQ, y_pQ = (p * Q_lifted).xy()
    
    phi_P = -x_pP / y_pP
    phi_Q = -x_pQ / y_pQ
    
    # Discrete log is the ratio k = phi(Q) / phi(P)
    return Integer(Mod(phi_Q / phi_P, p))


def main():    
    # Curve parameters
    p = 37596521231081692286097719226317294959438237380966990611426250022860049363722901792938760858989180414389198817978737
    a = 9980768944941555246412259964901404279221262365843204377450275584172813162519191945154105581021730623506736610561436
    b = 6204302295427697621568533586763401593326903936424761465051089911662954021106621122465925081755300614989243091933253
    
    # Points
    Gx = 15447065612664874603863922074709843217617947300821194509895141112376379689800058863402477048383987615075331617146523
    Ax = 10577607971208571434119391805999854179572624626504025910910768124944865520669643879346931306961545644496867645040277
    
    # Setup curve
    E = EllipticCurve(GF(p), [a, b])
    G = E.lift_x(GF(p)(Gx))
    A = E.lift_x(GF(p)(Ax))
    
    if E.order() != p:
        print(f"Curve is NOT anomalous - attack not applicable")
        print(f"   Order: {E.order()}")
        print(f"   Prime: {p}")
        print(f"Smart's attack only works when #E(F_p) = p")
        return
    
    print(f"Curve is anomalous (#E = p)")
    print(f"Solving A = d*G...")
    
    # Execute attack
    try:
        d = smart_attack(G, A, p, prec=8)
        
        # Verify
        if A == d * G:
            print(f"Attack succeeded!")
            print(f"d = {d}")
        else:
            print(f"Verification failed: A != d*G")
            
    except Exception as e:
        print(f"Attack failed: {e}")


if __name__ == "__main__":
    main()