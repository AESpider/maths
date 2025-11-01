#!/usr/bin/env python3
"""
Side-channel CPA attack on AES (HW(SBOX) leakage model).

Simulation of a side-channel (power/EM) attack using Correlation Power Analysis (CPA).

  - Target: AES-128, single-byte leakage modeled as Hamming weight of SBOX(pt ^ key).
  - Traces: synthetic noisy traces with gaussian temporal spread per byte.
  - Recovery: CPA (HW(SBOX)) per-byte, scoring candidates by peak absolute correlation.

Requirements: matplotlib, numpy, pycryptodome
Usage: python3 cpa_attack_hw.py
"""

import os
import numpy as np
import matplotlib.pyplot as plt
from Crypto.Cipher import AES

# parameters
N_TRACES = 400
N_SAMPLES = 3000
N_BYTES = 16
SAMPLE_BASE = 800      # sample index where leakage peaks start
SAMPLE_SEP = 7         # separation between byte peaks
ALPHA = 2.2            # signal amplitude
NOISE_STD = 1.0
OUT_DIR = "cpa_output"


# AES S-box and HW table
SBOX = np.array([
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
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16], dtype=np.uint8)
HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


def inject_per_byte_leakage(traces, PT, key, sample_base=SAMPLE_BASE, sample_sep=SAMPLE_SEP, alpha=ALPHA):
    # inject per-byte leakage (HW of SBOX(PT ^ key)) at different sample indices
    n_traces, n_samples = traces.shape
    t = np.arange(n_samples)
    for b in range(N_BYTES):
        idx = sample_base + b * sample_sep
        if idx >= n_samples:
            raise RuntimeError("increase N_SAMPLES or reduce SAMPLE_BASE/SAMPLE_SEP")
        xor = np.bitwise_xor(PT[:, b], key[b])
        val = HW[SBOX[xor]].astype(np.float64)
        # gaussian-shaped temporal spread for realism
        spread = np.exp(-0.5 * ((t - idx) / 2.0) ** 2)
        spread = spread / spread.max()
        traces += (alpha * val)[:, None] * spread[None, :]


def cpa_recover(traces, PT):
    # CPA vectorized recovery (HW(SBOX(...)) model)
    traces_centered = traces - traces.mean(axis=0)
    traces_ss = (traces_centered ** 2).sum(axis=0)

    recovered = np.zeros(N_BYTES, dtype=np.uint8)
    scores = np.zeros((N_BYTES, 256), dtype=np.float64)

    for b in range(N_BYTES):
        pt = PT[:, b].astype(np.uint8)
        keys_vec = np.arange(256, dtype=np.uint8)[:, None]         # (256,1)
        xor = np.bitwise_xor(keys_vec, pt[None, :])                # (256, n_traces)
        hyp = SBOX[xor]                                            # (256, n_traces)
        hyp_hw = HW[hyp].astype(np.float64)                        # (256, n_traces)
        hyp_mean = hyp_hw.mean(axis=1, keepdims=True)
        hyp_centered = hyp_hw - hyp_mean                           # center hypothesis
        numerator = hyp_centered.dot(traces_centered)              # (256, n_samples)
        hyp_ss = (hyp_centered ** 2).sum(axis=1)
        hyp_ss[hyp_ss == 0] = 1e-12
        denom = np.sqrt(hyp_ss[:, None] * traces_ss[None, :])
        corr = numerator / denom                                   # correlation map
        peak = np.max(np.abs(corr), axis=1)                        # one score per candidate
        scores[b, :] = peak
        best = int(np.argmax(peak))
        recovered[b] = best
        print(f"byte {b:2d}: recovered 0x{best:02x} peak {peak[best]:.6f}")

    return recovered, scores, traces_centered, traces_ss


def save_outputs(out_dir: str, scores: np.ndarray, PT: np.ndarray, CT: np.ndarray, rec_key_hex: str, traces: np.ndarray) -> None:
    """Create output directory and save results"""
    os.makedirs(out_dir, exist_ok=True)
    np.save(os.path.join(out_dir, "scores.npy"), scores)
    np.save(os.path.join(out_dir, "PT.npy"), PT)
    np.save(os.path.join(out_dir, "CT.npy"), CT)
    
    # Save traces in .bini8 format
    traces_int8 = np.clip(np.round(traces), -128, 127).astype(np.int8)
    traces_int8.tofile(os.path.join(out_dir, "traces.bini8"))
    
    with open(os.path.join(out_dir, "recovered_key_hex.txt"), "w") as f:
        f.write(rec_key_hex)
    print(f"Saved outputs in {out_dir}")

def plot_diagnostics(out_dir: str, scores: np.ndarray, traces: np.ndarray, key: np.ndarray, PT: np.ndarray) -> None:
    """Save diagnostic plots (byte0 scores and true-byte correlation) as PNG files in out_dir."""
    plt.figure(figsize=(8, 3))
    plt.plot(np.arange(256), scores[0, :])
    plt.xlabel("Key candidate")
    plt.ylabel("Peak abs(correlation)")
    plt.title("Byte 0: CPA peak per candidate")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "byte0_scores.png"))
    plt.close()

    # correlation for true key byte 0 (for inspection)
    true_k0 = int(key[0])
    pt0 = PT[:, 0].astype(np.uint8)
    keys_vec = np.array([true_k0], dtype=np.uint8)[:, None]
    xor_true = np.bitwise_xor(keys_vec, pt0[None, :])
    hyp_true = SBOX[xor_true]
    hyp_hw_true = HW[hyp_true].astype(np.float64)
    hyp_centered_true = hyp_hw_true - hyp_hw_true.mean(axis=1, keepdims=True)
    traces_centered = traces - traces.mean(axis=0)
    numerator_true = hyp_centered_true.dot(traces_centered)
    hyp_ss_true = (hyp_centered_true ** 2).sum(axis=1)
    denom_true = np.sqrt(hyp_ss_true[:, None] * (traces_centered ** 2).sum(axis=0)[None, :])
    corr_true = (numerator_true / denom_true).flatten()

    plt.figure(figsize=(10, 3))
    plt.plot(corr_true)
    plt.axvline(SAMPLE_BASE, linestyle="--")
    plt.xlabel("Sample index")
    plt.ylabel("Correlation")
    plt.title(f"Correlation for byte 0, true key 0x{true_k0:02x}")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "byte0_corr_true.png"))
    plt.close()


if __name__ == "__main__":
    print("Starting CPA side-channel attack simulation on AES (HW model)\n")

    # simulate key, plaintexts and noisy traces
    key = np.random.randint(0, 256, size=(N_BYTES,), dtype=np.uint8)
    PT = np.random.randint(0, 256, size=(N_TRACES, N_BYTES), dtype=np.uint8)

    # Initial traces (Gaussian noise)
    traces = np.random.normal(0.0, NOISE_STD, size=(N_TRACES, N_SAMPLES)).astype(np.float64)

    inject_per_byte_leakage(traces, PT, key)

    recovered, scores, traces_centered, traces_ss = cpa_recover(traces, PT)

    rec_key = bytes(recovered.tolist())
    print("\nRecovered key (hex):", rec_key.hex())
    print("Match ?", bytes(key.tolist()).hex() == rec_key.hex())


    # verify by AES-ECB encryption
    cipher = AES.new(rec_key, AES.MODE_ECB)
    enc_blocks = [cipher.encrypt(bytes(PT[i].tolist())) for i in range(N_TRACES)]
    enc_arr = np.frombuffer(b''.join(enc_blocks), dtype=np.uint8).reshape((N_TRACES, N_BYTES))

    # save outputs and plots
    save_outputs(OUT_DIR, scores, PT, enc_arr, rec_key.hex(), traces)
    plot_diagnostics(OUT_DIR, scores, traces, key, PT)
