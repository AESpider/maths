#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES-128 single-bit fault attack.

Fault model: single-bit flip in round 9, random positions

Use differences between correct and faulty ciphertexts; apply INV-SBOX 
and the known effect of MixColumns on unit vectors to recover K10 
column-by-column. Intersect candidate sets from many fault traces and 
validate candidates by inverting the key schedule and re-expanding keys.

Usage: python3 r9_fault_attack.py
"""

import random
from itertools import product
from collections import defaultdict

# AES tables
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
# Inverse S-box 
INV_S = [0]*256
for i,v in enumerate(SBOX):
    INV_S[v] = i

# AES rcon
rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

# GF(2^8) multiply-by-x
def xtime(a):
    return ((a << 1) & 0xff) ^ ((a >> 7) * 0x1b)

# In-place MixColumns on a 4-byte column
def mixcolumn(b):
    u = b[0];   t = b[0] ^ b[1] ^ b[2] ^ b[3]
    v = xtime(b[0] ^ b[1]);   b[0] ^= v ^ t
    v = xtime(b[1] ^ b[2]);   b[1] ^= v ^ t
    v = xtime(b[2] ^ b[3]);   b[2] ^= v ^ t
    v = xtime(b[3] ^ u);      b[3] ^= v ^ t

# Compute MixColumns result when input is a unit vector 
def MC_on_unit(p,e):
    col = [0,0,0,0]; col[p] = e
    colc = col.copy(); mixcolumn(colc)
    return tuple(colc)

# Precompute bitmasks and expected MixColumns outputs for unit vectors
BITMASKS = [1 << b for b in range(8)]
EXPECTED_MC = {(p,e): MC_on_unit(p,e) for p in range(4) for e in BITMASKS}

# Key expansion returning list of 44 words (as 4-byte lists)
def key_expansion(masterkey):
    roundkeys = [masterkey[i:i+4] for i in range(0, 16, 4)]  # words w0..w3
    for rnd in range(10):
        for j in range(4):
            tmp = roundkeys[-1].copy()
            if j == 0:
                # RotWord + SubWord + rcon for every new word at positions multiple of 4
                tmp = tmp[1:] + tmp[:1]
                tmp = [SBOX[t] for t in tmp]
                tmp[0] ^= rcon[rnd]
            # xor with word 4 rounds before
            roundkeys.append([tmp[i] ^ roundkeys[rnd*4 + j][i] for i in range(4)])
    return roundkeys

# Apply SBOX to every byte in the state
def sub_bytes(state):
    for i in range(4):
        state[i] = [SBOX[b] for b in state[i]]

# ShiftRows for column-major
def shift_rows(state):
    # row 1
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    # row 2
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    # row 3
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

# Apply MixColumns to each column
def mix_columns(state):
    for c in state:
        mixcolumn(c)

# XOR round key words (4 words) into the state. round_index is 0..10.
def add_round_key(state, roundkeys, round_index):
    base = round_index * 4
    for i in range(4):
        for j in range(4):
            state[i][j] ^= roundkeys[base + i][j]

# AES-128 encryption with optional single-byte fault at a given round and position
def encrypt_aes_once(plaintext, masterkey, fault_round=None, fault_pos=None, fault=None):
    roundkeys = key_expansion(masterkey)
    # state represented as 4 columns of 4 bytes
    state = [plaintext[i:i+4] for i in range(0,16,4)]

    # initial AddRoundKey (round 0)
    add_round_key(state, roundkeys, 0)

    # rounds 1..9 
    for rnd in range(1,10):
        sub_bytes(state)
        shift_rows(state)

        # optionally inject a single-byte fault (round 9 injection => rnd == 9)
        if rnd == fault_round and fault_pos is not None and fault is not None:
            col_idx = fault_pos // 4
            row_idx = fault_pos % 4
            state[col_idx][row_idx] ^= fault

        mix_columns(state)
        add_round_key(state, roundkeys, rnd)

    # final round 10 (SubBytes + ShiftRows + AddRoundKey)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, roundkeys, 10)

    # serialize ciphertext in column-major order to bytes
    ct = bytes([state[i][j] for i in range(4) for j in range(4)])
    return ct, roundkeys

# random key, plaintext and many single-bit faults at round 9
def tuples_for_pair_col(col, C_bytes, Cf_bytes):
    # idx mapping for column col : ciphertext byte indices corresponding to the 4 rows
    idxs = [ ((col - r) % 4)*4 + r for r in range(4) ]
    res = set()

    for p in range(4):
        for e in BITMASKS:
            expected = EXPECTED_MC[(p,e)]
            cand_per_byte = []
            ok = True
            for j, idx in enumerate(idxs):
                cbyte = C_bytes[idx]; cfbyte = Cf_bytes[idx]
                cands = []
                # try all possible k10 byte candidates (0..255)
                for k in range(256):
                    v = INV_S[cbyte ^ k]; vf = INV_S[cfbyte ^ k]
                    # require that the difference equals expected MixColumns output
                    if (v ^ vf) == expected[j]:
                        cands.append(k)
                if not cands:
                    ok = False; break
                cand_per_byte.append(cands)
            if ok:
                # cross-product of per-byte candidates gives full 4-byte tuples
                for tup in product(*cand_per_byte):
                    res.add(tup)
    return res

# Intersect candidates across multiple faulted ciphertexts for each column
column_candidates = [None]*4

def bytes_to_word(b0,b1,b2,b3):
    return (b0<<24)|(b1<<16)|(b2<<8)|b3

def word_to_bytes(w):
    return [(w>>24)&0xff, (w>>16)&0xff, (w>>8)&0xff, w&0xff]

def RotWord(w):
    return ((w<<8)&0xffffffff) | ((w>>24)&0xff)

def SubWord(w):
    b = word_to_bytes(w); return bytes_to_word(*[SBOX[x] for x in b])

def inv_key_schedule_from_k10(k10):
    # k10 is 16 bytes; construct words w[40..43]
    w = [None] * 44
    for i in range(4):
        w[40+i] = bytes_to_word(k10[4*i], k10[4*i+1], k10[4*i+2], k10[4*i+3])
    
    # walk backwards to compute w[i-4] = w[i] ^ (SubWord(RotWord(w[i-1])) ^ rcon) when i%4==0
    for i in range(43, 3, -1):
        temp = w[i-1]
        if i % 4 == 0:
            temp = SubWord(RotWord(temp)) ^ (rcon[(i//4)-1] << 24)
        w[i-4] = w[i] ^ temp
    
    # reconstruct master key bytes from w0..w3
    mk = []
    for i in range(4):
        mk += word_to_bytes(w[i])
    return mk

# number of faulty ciphertexts to generate (single-bit faults)
NUM_FAULT_TRACES = 31

if __name__ == "__main__":
    print("Fault attack on AES-128 - single-bit faults on round 9, recovering K10\n")

    # generate random key/plaintext
    masterkey = [random.randrange(0,256) for _ in range(16)]
    plaintext = [random.randrange(0,256) for _ in range(16)]
    C_correct, _ = encrypt_aes_once(plaintext, masterkey)

    # generate faulty ciphertexts
    pairs = []
    for _ in range(NUM_FAULT_TRACES):
        pos = random.randrange(0,16)            # random byte position to fault
        fault = 1 << random.randrange(0,8)      # random single-bit fault
        cf, _ = encrypt_aes_once(plaintext, masterkey, fault_round=9, fault_pos=pos, fault=fault)
        pairs.append((pos,fault,cf))

    # group faults by column
    groups = defaultdict(list)
    for pos,fault,cf in pairs:
        groups[pos//4].append((pos,fault,cf))


    column_candidates = [set() for _ in range(4)]
    for col in range(4):
        C_bytes = list(C_correct)
        cand = None
        for pos,fault,cf in groups[col]:
            tupset = tuples_for_pair_col(col, C_bytes, list(cf))
            if tupset:
                if cand is None:
                    cand = tupset.copy()
                else:
                    cand &= tupset
        column_candidates[col] = cand if cand is not None else set()
        print(f"col {col} candidates: {len(column_candidates[col])}")

    # assemble full K10 candidates by combining column tuples
    full_k10_candidates = []
    if all(column_candidates[col] for col in range(4)):
        for t0 in column_candidates[0]:
            for t1 in column_candidates[1]:
                for t2 in column_candidates[2]:
                    for t3 in column_candidates[3]:
                        k10 = [None]*16
                        for r,val in enumerate(t0):
                            idx = ((0 - r) % 4)*4 + r; k10[idx] = val
                        for r,val in enumerate(t1):
                            idx = ((1 - r) % 4)*4 + r; k10[idx] = val
                        for r,val in enumerate(t2):
                            idx = ((2 - r) % 4)*4 + r; k10[idx] = val
                        for r,val in enumerate(t3):
                            idx = ((3 - r) % 4)*4 + r; k10[idx] = val
                        if None not in k10:
                            full_k10_candidates.append(k10)

    print("Full K10 candidates:", len(full_k10_candidates))

    # Validate by inverting schedule and re-expanding
    recovered = []
    for k10 in full_k10_candidates:
        mk = inv_key_schedule_from_k10(k10)
        rk = key_expansion(mk)
        k10_from_mk = []
        for i in range(10*4, 10*4+4):
            k10_from_mk += rk[i]
        if k10_from_mk == k10:
            recovered.append(mk)

    if recovered:
        print("\nRecovered master key:", bytes(recovered[0]).hex())
        print("Match ?", recovered[0] == masterkey)
    else:
        print("No recovered master; show per-column per-byte candidate counts:")
        for col in range(4):
            cset = column_candidates[col] or set()
            per_byte = [set() for _ in range(4)]
            for tup in cset:
                for i,b in enumerate(tup):
                    per_byte[i].add(b)
            print(f"col {col} counts:", [len(s) for s in per_byte])
            for i,s in enumerate(per_byte):
                print(" sample:", sorted(list(s))[:20])
