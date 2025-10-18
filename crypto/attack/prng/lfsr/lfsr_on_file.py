#!/usr/bin/env python3
"""
LFSR-based file stream cipher

Implements:
  - LFSR keystream generator
  - File encryption/decryption by XOR with keystream
  - Simple known-plaintext attack (KPA) on common file signatures

Not cryptographically secure - for learning.

Usage:
  python3 lfsr_on_file.py encode [-p,--poly P] [-s,--state S] file
  python3 lfsr_on_file.py decode -p POLY -s STATE file.enc
  python3 lfsr_on_file.py crack file.enc [--known_plaintext PT]   # default: PNG header+IHDR
  python3 lfsr_on_file.py test [-p,--poly P] [-s,--state S] [-o,--on N]
"""

import argparse
import secrets
import time
import os
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from tqdm.auto import tqdm
except ImportError:
    def tqdm(x, *args, **kwargs):
        return x

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

# Constants
DEFAULT_TAPS = [60, 61, 63, 64]
DEFAULT_LFSR_LENGTH = 64

DEFAULT_CHUNK_SIZE = 1 << 20  # 1MB: 1024 * 1024

# PNG signature + IHDR length + 'IHDR' (16 bytes, 128 bits)
PNG_HEADER = b'\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR'

# Exemple: Common headers / signatures
COMMON_SIGNATURES = [
    PNG_HEADER,
    b'Rar!\x1a\x07\x01\x00',                   # RAR5 (8 bytes)
    b'7z\xbc\xaf\x27\x1c',                     # 7z (6 bytes)
    b'%PDF-',                                  # PDF prefix (5 bytes)
    b'\x7fELF',                                # ELF (4 bytes)
]

# Primitive polynomials for different lengths (taps for maximum period: 2^n-1)
PRIMITIVE_POLYNOMIALS = {
    3: [[3, 1]],                # period = 2^3-1 = 7
    4: [[4, 1]],                # 2^4-1 = 15
    5: [[5, 2]],                # 31
    6: [[6, 1]],                # 63
    7: [[7, 1]],                # 127
    8: [[8, 4, 3, 2]],          # 255
    16: [[16, 5, 3, 2]],        # 65535
    32: [[32, 7, 5, 3, 2, 1]],  # 4294967295
    DEFAULT_LFSR_LENGTH: [DEFAULT_TAPS] # 18,446,744,073,709,551,615 
}

# Known prime-factorizations of 2^n - 1 used for primitivity tests.
# To fully prove primitivity, add entries here for any additional n you care about.
FACTORS_2POW_MINUS1 = {
    3: [7],                   # 2^3-1 = 7
    4: [3,5],                 # 2^4-1 = 15 = 3*5
    5: [31],
    6: [3,7],                 # 63 = 3*3*7
    7: [127],
    8: [3,5,17],              # 255 = 3*5*17
    16: [3,5,17,257],         # 65535 = 255*257
    32: [3,5,17,257,65537],   # 2^32-1 = 255*257*65537
    DEFAULT_LFSR_LENGTH: [3,5,17,257,641,65537,6700417],  # 2^64-1 = 255*257*641*65537*6700417
}

# ----------------- helpers: polynomials over GF(2), LSB convention -----------------
def _poly_degree(p: int) -> int:
    return p.bit_length() - 1 if p else -1

def _poly_from_taps(taps: List[int], length: int) -> int:
    """Return integer representing polynomial f(x) = 1 + sum_{t in taps} x^t.
       taps may include the 'length' term (x^length)."""
    f = 1  # constant term
    for t in taps:
        t = int(t)
        if t < 0:
            raise ValueError("tap must be positive")
        f |= (1 << t)
    # Ensure polynomial degree is exactly length (i.e. x^length present)
    if (f >> length) & 1 == 0:
        # If taps didn't include the top degree, add it so polynomial matches LFSR length
        f |= (1 << length)
    return f

def _poly_gcd(a: int, b: int) -> int:
    if a == 0:
        return b
    if b == 0:
        return a
    A, B = a, b
    while B:
        r = A
        degB = _poly_degree(B)
        while _poly_degree(r) >= degB and r != 0:
            shift = _poly_degree(r) - degB
            r ^= (B << shift)
        A, B = B, r
    return A

def _prime_divisors(n: int) -> List[int]:
    r = []
    d = 2
    nn = n
    while d * d <= nn:
        if nn % d == 0:
            r.append(d)
            while nn % d == 0:
                nn //= d
        d += 1 if d == 2 else 2
    if nn > 1:
        r.append(nn)
    return r

_SQR_TABLE = None
def _build_sqr_table():
    global _SQR_TABLE
    if _SQR_TABLE is not None:
        return
    T = [0] * 256
    for v in range(256):
        t = 0
        for i in range(8):
            if (v >> i) & 1:
                t |= (1 << (2 * i))
        T[v] = t
    _SQR_TABLE = T

def _poly_square(a: int) -> int:
    """Squaring using 8-bit lookup (bit i -> bit 2*i)."""
    if a == 0:
        return 0
    _build_sqr_table()
    res = 0
    shift_out = 0
    aa = a
    while aa:
        res |= (_SQR_TABLE[aa & 0xFF] << shift_out)
        aa >>= 8
        shift_out += 16
    return res

def _poly_mod_reduce(a: int, mod: int) -> int:
    """Reduce polynomial a modulo mod."""
    deg_mod = _poly_degree(mod)
    while True:
        deg_a = _poly_degree(a)
        if deg_a < deg_mod:
            break
        a ^= (mod << (deg_a - deg_mod))
    return a

def _poly_mul_mod(a: int, b: int, mod: int) -> int:
    """"Multiply a*b in GF(2)[x] and reduce modulo mod."""
    if a == 0 or b == 0:
        return 0
    res = 0
    aa = a
    bb = b
    while bb:
        lsb = bb & -bb
        shift = lsb.bit_length() - 1
        res ^= (aa << shift)
        bb ^= lsb
    return _poly_mod_reduce(res, mod)

def _poly_pow_mod(base: int, exp: int, mod: int) -> int:
    res = 1
    b = base
    e = exp
    while e:
        if e & 1:
            res = _poly_mul_mod(res, b, mod)
        e >>= 1
        if e:
            b = _poly_mul_mod(b, b, mod)
    return res

def _poly_x_pow_2k_table(f: int, n: int) -> List[int]:
    """Build F where F[i] = x^{2^i} mod f for i=0..n (F[0]=2)."""
    F = [0] * (n + 1)
    F[0] = 2  # x
    for i in range(1, n + 1):
        sq = _poly_square(F[i-1])
        F[i] = _poly_mod_reduce(sq, f)
    return F

def pow_from_frobenius(E: int, F: List[int], mod: int) -> int:
    """Compute x^E by multiplying the F[i] for which bit i of E is 1."""
    res = 1
    i = 0
    ee = E
    while ee:
        if ee & 1:
            res = _poly_mul_mod(res, F[i], mod)
        ee >>= 1
        i += 1
    return res

def lucas_lehmer(p: int) -> bool:
    """
    Lucas-Lehmer test for Mersenne numbers: returns True iff 2^p - 1 is prime.
    Assumes p is an integer >= 2. Deterministic.
    """
    if p == 2:
        return True
    M = (1 << p) - 1  # 2^p - 1
    s = 4
    for _ in range(p - 2):
        s = (s * s - 2) % M
    return s == 0

def is_likely_primitive(taps: List[int], length: int) -> Tuple[bool, bool]:
    """
    Test if a polynomial (from LFSR taps) is primitive.

    Returns (is_primitive, fully_tested):
      - is_primitive: False if proven non-primitive, True if passes all available tests
      - fully_tested: True if we tested all prime factors of 2^n-1, False if only partial testing

    Process:
      1. First checks if polynomial is irreducible (necessary condition for primitivity)
      2. Then tests primitivity using known prime factors of 2^n-1

    NOTE: If FACTORS_2POW_MINUS1 lacks complete factorization for n, 
    we return (True, False) after passing irreducibility - probable primitive only.
    """
    n = int(length)
    f = _poly_from_taps(taps, n)
    
    if _poly_degree(f) != n:
        # polynomial degree mismatch -> invalid for this LFSR length
        return False, True
    
    # precompute Frobenius powers x^{2^k} mod f for efficiency
    F = _poly_x_pow_2k_table(f, n)
    
    # Rabin irreducibility test
    # For each prime divisor q of n, check gcd(x^{2^{n/q}} - x, f) == 1
    for q in _prime_divisors(n):
        k = n // q
        xp = F[k]  # x^{2^k} mod f
        if _poly_gcd(xp ^ 2, f) != 1:  # xp - x where x ≡ 2 in our representation
            return False, True
    
    # check x^{2^n} = x (mod f)
    if F[n] != F[0]:
        return False, True
    
    # Primitivity test using prime factors of 2^n - 1
    two_n_minus_1 = (1 << n) - 1
    factors = FACTORS_2POW_MINUS1.get(n)
    
    if factors is None:
        # TODO: Implement full factorization of 2^n-1 for complete primitivity test
        factors = []
        partial = True
    else:
        partial = False
    
    # For each prime factor r of 2^n-1, verify x^{(2^n-1)/r} != 1 (mod f)
    # If any equals 1, then order of x divides (2^n-1)/r, so not primitive
    for r in factors:
        exp = two_n_minus_1 // r
        if pow_from_frobenius(exp, F, f) == 1:
            return False, True  # proven non-primitive
    
    if partial:
        # passed irreducibility + partial primitivity tests
        return True, False
    
    # passed complete primitivity test
    return True, True

# ---------------- LFSR ----------------
class LFSR:
    def __init__(self, taps: List[int], initial_state: Optional[int] = None, length: int = DEFAULT_LFSR_LENGTH):
        self.length = int(length)
        self.mask = self._taps_to_mask(taps)
        
        # Verify whether taps likely give maximum period
        is_prim, fully_tested = is_likely_primitive(taps, self.length)
        if not is_prim:
            print(f"Warning: Taps {taps} may not produce maximum period for LFSR length {self.length}")
        elif not fully_tested:
            print(f"Warning: Could not fully verify primitivity for length {self.length}; taps {taps} passed partial tests and are likely primitive")
          
        if initial_state is None:
            self.state = secrets.randbits(self.length)
            while self.state == 0:
                self.state = secrets.randbits(self.length)
        else:
            self.state = int(initial_state) & ((1 << self.length) - 1)
            if self.state == 0:
                raise ValueError("Initial state cannot be 0")

    def _taps_to_mask(self, taps: List[int]) -> int:
        mask = 0
        for tap in taps:
            pos = self.length - int(tap)
            mask |= (1 << pos)
        return mask

    def step(self) -> int:
        """ Single step - uses bit_count for popcount. """
        out = self.state & 1
        fb = (self.state & self.mask).bit_count() & 1
        self.state = (self.state >> 1) | (fb << (self.length - 1))
        self.state &= (1 << self.length) - 1
        return out
    
    def generate_keystream_bytes(self, num_bytes: int) -> bytearray:
        """ Produces MSB-first bits per byte - avoids calling self.step() 8 times per byte."""
        st = self.state
        mask = self.mask
        L = self.length
        out = bytearray(num_bytes)
        mv = memoryview(out)
        top_shift = L - 1
        cmask = (1 << L) - 1
        for bi in range(num_bytes):
            b = 0
            # unroll 8 steps
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            bit = st & 1; fb = (st & mask).bit_count() & 1; st = (st >> 1) | (fb << top_shift); b = (b << 1) | (bit & 1)
            mv[bi] = b
        self.state = st & cmask
        return out
    

# ---------------- Encrypt / Decrypt (chunked, in-place XOR) ----------------
def xor_chunks(chunk_data: bytes, keystream: bytes) -> bytearray:
    """
    XOR chunk_data ^ keystream and return bytearray(result).
    Both inputs must have equal length.
    """
    if NUMPY_AVAILABLE:
        # vectorized
        chunk_array = np.frombuffer(chunk_data, dtype=np.uint8)
        keystream_array = np.frombuffer(keystream, dtype=np.uint8)
        result = np.bitwise_xor(chunk_array, keystream_array)
        return bytearray(result.tobytes())
    else:
        chunk_b = bytearray(chunk_data) # in-place
        for i in range(len(chunk_b)): 
            chunk_b[i] ^= keystream[i]
        return chunk_b
    

def encrypt_file(filepath: str, taps: List[int], initial_state: Optional[int] = None,
                 length: int = DEFAULT_LFSR_LENGTH, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Tuple[str, int, List[int]]:
    lfsr = LFSR(taps, initial_state, length)
    initial_used = lfsr.state

    outpath = filepath + ".enc"
    with open(filepath, "rb") as fin, open(outpath, "wb") as fout:
        while chunk := fin.read(chunk_size):
            keystream = lfsr.generate_keystream_bytes(len(chunk))
            encrypted_chunk = xor_chunks(chunk, keystream)
            fout.write(encrypted_chunk)

    return outpath, initial_used, taps

def decrypt_file(filepath: str, taps: List[int], initial_state: int,
                 length: int = DEFAULT_LFSR_LENGTH, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    lfsr = LFSR(taps, initial_state, length)

    p = Path(filepath)
    if p.suffix == ".enc":  # remove only final .enc      
        outpath = str(p.with_name(p.name[:-4]))
    else:
        outpath = filepath + ".dec"

    with open(filepath, "rb") as fin, open(outpath, "wb") as fout:
        while chunk := fin.read(chunk_size):
            keystream = lfsr.generate_keystream_bytes(len(chunk))
            decrypted_chunk = xor_chunks(chunk, keystream)
            fout.write(decrypted_chunk)
                
    return outpath

# ---------------- Berlekamp-Massey GF(2) ----------------
def berlekamp_massey_gf2(bits: List[int]) -> Tuple[int, List[int]]:
    """
    Berlekamp–Massey algorithm optimized for GF(2).
    Returns (L, poly):
      - L is the linear complexity (the degree of the minimal polynomial),
      - poly is the list of coefficients [1, c1, c2, ..., cL] with c_i in {0,1}.

    `bits` is a list of 0/1 values where bits[t] is the t-th term of the sequence. 
    The returned feedback polynomial C(x) respect the recurrence:
        s[t] = c1*s[t-1] + c2*s[t-2] + ... + cL*s[t-L]  (mod 2).
    """

    n = len(bits)
    if n == 0:
        return 0, [1]

    # Polynomials stored as integers: bit i = coeff x^i.
    C = 1    # feedback poly C(x) (starts as 1)
    B = 1    # previous C saved as integer
    L = 0
    m = 1    # distance since last update of L/B
    # window: bit0 = s[t-1], bit1 = s[t-2], ...
    window = 0

    for t in range(n):
        # discrepancy d = s[t] + sum_{i=1..L} c_i * s[t-i]  (mod 2)
        # (C >> 1) has bits c1.. at positions 0..
        dot = (C >> 1) & window
        d = bits[t] ^ (dot.bit_count() & 1)

        if d:
            T = C
            # C <- C + x^m * B  (over GF(2) '+' == XOR)
            C = C ^ (B << m)
            if 2 * L <= t:
                # update L, B, reset m
                L_new = t + 1 - L
                B = T
                L = L_new
                m = 1
            else:
                m += 1
        else:
            m += 1

        # shift window: insert s[t] as the newest past bit for next iteration
        window = ((window << 1) | (bits[t] & 1))

    # extract coefficients c1..cL as bits of C >> 1
    poly = [1] + [ ((C >> i) & 1) for i in range(1, L + 1) ]
    return L, poly

# ---------------- helpers: crack ----------------
def bytes_to_bits(b: bytes) -> List[int]:
    bits = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits

def bits_to_int_msbf(bits: List[int]) -> int:
    v = 0
    for bit in bits:
        v = (v << 1) | (bit & 1)
    return v

def bits_to_int_lsbf(bits: List[int]) -> int:
    v = 0
    for i, b in enumerate(bits):
        if b & 1:
            v |= (1 << i)
    return v

# ---------------- CRACK (known-plaintext attack) ----------------
def crack_lfsr(ciphertext_path: str, known_plaintext: Optional[bytes] = None):
    """
    Known-plaintext attack on LFSR cipher.
    Uses Berlekamp-Massey to detect LFSR length and coefficients.
    Returns (taps, initial_state) if successful, None otherwise.
    """
    if known_plaintext is None:
        known_plaintext = PNG_HEADER
    size = len(known_plaintext)

    with open(ciphertext_path, "rb") as f:
        ciphertext = f.read(size)

    # print(f"Size: {size} bytes")
    # print(f"Ciphertext: {ciphertext.hex()}")
    # print(f"Known plaintext: {known_plaintext.hex()}")

    # compute keystream bytes for known prefix
    keystream_known_bytes = bytes([ciphertext[i] ^ known_plaintext[i] for i in range(size)])
    keystream_bits = bytes_to_bits(keystream_known_bytes)
    
    L_found, poly = berlekamp_massey_gf2(keystream_bits)
    
    # poly = [1, c1, c2, ..., c_L_found]
    taps = [i + 1 for i in range(L_found) if poly[i + 1] == 1]
    initial_state = bits_to_int_lsbf(keystream_bits[:L_found])

    l = LFSR(taps, initial_state, L_found)
    keystream = l.generate_keystream_bytes(size)
    plaintext = bytes([ciphertext[i] ^ keystream[i] for i in range(size)])

    if plaintext == known_plaintext:
        return L_found ,taps, initial_state

    # if none matched, return None to indicate failure
    return None

# ---------------- Performance test ----------------
def performance_test(taps: List[int], initial_state: Optional[int], length: int, gib: float):
    total_bytes = int(gib * 1024**3)
    if total_bytes <= 0:
        print("Invalid size")
        return
    
    n_chunks = (total_bytes + DEFAULT_CHUNK_SIZE - 1) // DEFAULT_CHUNK_SIZE  # total chunks

    lfsr = LFSR(taps, initial_state, length)
    initial_used = lfsr.state

    print(f"Performance test: generating {gib:.3f} GiB of keystream ({total_bytes} bytes)")
    print(f"Total chunks to process: {n_chunks}")
    print(f"Polynomial taps: {taps}")
    print(f"Initial state (hex): 0x{initial_used:{(length+3)//4}x}")
    
    generated = 0
    t0 = time.time()
    for _ in tqdm(range(n_chunks)):
        need = min(DEFAULT_CHUNK_SIZE, total_bytes - generated)
        keystream = lfsr.generate_keystream_bytes(need)
        dummy_data = bytearray(need) 
        xor_chunks(keystream, dummy_data)
        generated += need
    t1 = time.time()

    elapsed = t1 - t0
    mb = total_bytes / (1024**2)
    print(f"Total time: {elapsed:.4f} s")
    print(f"Throughput: {mb/elapsed:.2f} MiB/s ({(mb/1024)/elapsed:.4f} GiB/s)")

# ---------------- Utilities ----------------
def parse_poly_string(s: Optional[str], default_length: int = DEFAULT_LFSR_LENGTH) -> List[int]:
    if s is None:
        if default_length in PRIMITIVE_POLYNOMIALS:
            return PRIMITIVE_POLYNOMIALS[default_length][0]
        else:
            available_lengths = sorted(PRIMITIVE_POLYNOMIALS.keys())
            raise ValueError(
                f"No default primitive polynomial available for length {default_length}. "
                f"Please specify taps with -p/--poly option. "
                f"Available default lengths: {available_lengths}"
            )
    try:
        raw = s.strip()
        if raw.startswith("[") and raw.endswith("]"):
            raw = raw[1:-1]

        if "," in raw: # split by comma or whitespace
            parts = [p.strip() for p in raw.split(",") if p.strip() != ""]
        else:
            parts = [p for p in raw.split() if p != ""]

        taps = [int(p, 0) for p in parts]
        if not taps or any(t <= 0 or t > default_length for t in taps):
            raise ValueError("Invalid taps: must be 1 <= tap <= {}".format(default_length))
        return taps
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid polynomial format: {e}")

def parse_state_string(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    raw = s.strip().lower()
    # allow hex 0x..., binary 0b..., or decimal
    try:
        if raw.startswith("0x"):
            return int(raw, 16)
        if raw.startswith("0b"):
            return int(raw, 2)
        if all(ch in "0123456789" for ch in raw):
            return int(raw, 10)
        
        # fallback: try int with base 0
        return int(raw, 0)
    except Exception:
        raise argparse.ArgumentTypeError("State must be hex (0x..), binary (0b..), or decimal.")

def parse_known_plaintext_arg(s: Optional[str]) -> Optional[bytes]:
    if s is None:
        return None
    s = s.strip()
    try:
        if s.startswith("0x"):
            return bytes.fromhex(s[2:])
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
            return bytes.fromhex(s)
        
        return s.encode("utf-8")
    except Exception:
        raise argparse.ArgumentTypeError("known_plaintext must be hex (0x...) or literal text.")

def build_argparser():
    p = argparse.ArgumentParser(prog="lfsr_on_file.py", description="LFSR-based file XOR (encode/decode/crack/test).")
    sub = p.add_subparsers(dest="cmd", required=True)
    
    enc = sub.add_parser("encode", help="Encrypt a file with LFSR XOR keystream.")
    enc.add_argument("file", help="Input file to encrypt")
    enc.add_argument("-p", "--poly", help=f"Polynomial taps (e.g. '60,61,63,64', default {DEFAULT_TAPS})", default=None)
    enc.add_argument("-s", "--state", help="Initial state (decimal, hex 0x or bin 0b)", default=None)
    enc.add_argument("-l", "--length", help=f"LFSR length in bits (default {DEFAULT_LFSR_LENGTH})", type=int, default=DEFAULT_LFSR_LENGTH)

    dec = sub.add_parser("decode", help="Decrypt a file encrypted with this LFSR scheme.")
    dec.add_argument("file", help="Encrypted file (.enc)")
    dec.add_argument("-p", "--poly", help="Polynomial taps (e.g. '60,61,63,64')", required=True)
    dec.add_argument("-s", "--state", help="Initial state used for encryption (decimal, hex 0x or bin 0b)", required=True)
    dec.add_argument("-l", "--length", help="LFSR length in bits", type=int, default=DEFAULT_LFSR_LENGTH)

    crack = sub.add_parser("crack", help="Try known-plaintext attack (PNG default).")
    crack.add_argument("file", help="Encrypted PNG file (.enc) to attack")
    crack.add_argument("--known_plaintext", help="Known plaintext (hex or raw). Default: PNG header+IHDR", default=None)

    test = sub.add_parser("test", help="Performance test: generate N GiB of keystream.")
    test.add_argument("-p", "--poly", help=f"Polynomial taps (e.g. '60,61,63,64', default {DEFAULT_TAPS})", default=None)
    test.add_argument("-s", "--state", help="Initial state (decimal, hex 0x or bin 0b)", default=None)
    test.add_argument("-l", "--length", help=f"LFSR length in bits (default {DEFAULT_LFSR_LENGTH})", type=int, default=DEFAULT_LFSR_LENGTH)
    test.add_argument("-o", "--on", help="Amount of data to generate in GiB (float). Default 0.01 GiB", type=float, default=0.1)
    return p

def main():
    parser = build_argparser()
    args = parser.parse_args()
    try:
        if args.cmd == "encode":
            taps = parse_poly_string(args.poly, default_length=args.length)
            state_val = parse_state_string(args.state)
            hex_digits = (args.length + 3) // 4
            outpath, initial_used, taps_used = encrypt_file(args.file, taps, state_val, args.length)
            print(f"File encrypted -> {outpath}")
            print(f"Polynomial taps used: {taps_used}")
            print(f"Initial state (hex): 0x{initial_used:0{hex_digits}x}")
            print("To decrypt, run:")
            print(f"  python3 {os.path.basename(__file__)} decode -p \"{','.join(map(str,taps_used))}\" -s 0x{initial_used:0{hex_digits}x} {outpath}")

        elif args.cmd == "decode":
            taps = parse_poly_string(args.poly, default_length=args.length)
            state_val = parse_state_string(args.state)
            if state_val is None:
                raise ValueError("You must provide --state for decode.")
            out = decrypt_file(args.file, taps, state_val, args.length)
            print(f"Decrypted output -> {out}")

        elif args.cmd == "crack":
            kp = parse_known_plaintext_arg(args.known_plaintext)
            print("Attempting known-plaintext attack..")
            result = crack_lfsr(args.file, kp)
            if result is None:
                print("Attack failed.")
            else:
                L_found, taps_recovered, state_recovered = result
                hex_digits = (L_found + 3) // 4

                print(f"Taps recovered: {taps_recovered}")
                print(f"Initial state (hex): 0x{state_recovered:0{hex_digits}x}")
                try:
                    out = decrypt_file(args.file, taps_recovered, state_recovered, L_found)
                    print(f"Decrypted output -> {out}")
                except Exception as e:
                    print(f"Decryption failed: {e}")

        elif args.cmd == "test":
            taps = parse_poly_string(args.poly, default_length=args.length)
            state_val = parse_state_string(args.state)
            performance_test(taps, state_val, args.length, args.on)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
