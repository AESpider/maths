#!/usr/bin/env python3
"""
Multiprocess dictionary HMAC brute-forcer
Usage: python3 hmac_bf.py output.json path/to/wordlist.txt
"""
import sys
import json
import hmac
import hashlib
from pathlib import Path
import multiprocessing as mp
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Config
BATCH_SIZE = 2000
PROGRESS_REPORT = 1_000_000
MAX_TASKS_PER_CHILD = None # optional: maxtasksperchild

# Globals that will be set in worker processes by initializer
REQUIRED_FIELDS = ["iv", "c", "h"]
GV_IV = None
GV_CIPHERTEXT = None
GV_TARGET_HMAC = None

def init_worker(iv, ciphertext, target_hmac):
    """Initializer for pool workers: set globals (avoids pickling them each task)."""
    global GV_IV, GV_CIPHERTEXT, GV_TARGET_HMAC
    GV_IV = iv
    GV_CIPHERTEXT = ciphertext
    GV_TARGET_HMAC = target_hmac

def worker_check(batch):
    """
    Process a batch of passwords (is list of bytes).
    Returns tuple:
      (password_str, plaintext_str, tried_count) if found
      (None, None, tried_count) if not found
    """
    tried = 0
    for pw in batch:
        if not pw:
            continue
        tried += 1

        # HMAC(key=pw, msg="MasterCSI")
        digest = hmac.new(pw, b"Fixed_Salt", hashlib.sha256).hexdigest()

        if hmac.compare_digest(digest, GV_TARGET_HMAC):
            # derive AES key from pw (sha256 -> 32 bytes -> AES-256)
            key = hashlib.sha256(pw).digest()
            cipher = AES.new(key, AES.MODE_CBC, GV_IV)
            
            try:
                plaintext = unpad(cipher.decrypt(GV_CIPHERTEXT), AES.block_size)
                return pw.decode(errors="replace"), plaintext.decode(errors="replace"), tried
            
            except Exception as e:
                # continue searching
                print(f"[!] HMAC match but decrypt failed (maybe different derivation): {e}", file=sys.stderr)
                continue
            
    return None, None, tried

def iter_batches(wordlist_path, batch_size):
    """Yield batches of passwords (bytes)."""
    batch = []
    with open(wordlist_path, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if pw: 
                 batch.append(pw)

            if len(batch) >= batch_size:
                yield batch
                batch = []
        
        if batch:
            yield batch

def load_data(output_file):
    try:
        with open(output_file, "r") as f:
            data = json.load(f)
            
        for field in REQUIRED_FIELDS:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")
        
        iv = bytes.fromhex(data["iv"])
        ciphertext = bytes.fromhex(data["c"])
        target_hmac = data["h"].lower()
        
        return iv, ciphertext, target_hmac
        
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {output_file}: {e}")
    except ValueError as e:
        raise ValueError(f"Invalid hex data in {output_file}: {e}")

def main():
    if len(sys.argv) != 3:
        print("Multiprocess HMAC brute-forcer")
        print(f"Usage: {sys.argv[0]} <output.json> <wordlist.txt>")
        sys.exit(1)

    output_file, wordlist_file = sys.argv[1], sys.argv[2]

    if not Path(output_file).exists():
        print(f"[!] Error: Output file does not exist: {output_file}")
        return 1
    
    if not Path(wordlist_file).exists():
        print(f"[!] Error: Wordlist file does not exist: {wordlist_file}")
        return 1
    
    print("[*] Loading data...")
    iv, ciphertext, target_hmac = load_data(output_file)

    print(f"Target HMAC: {target_hmac}")

    cpu_count = max(1, mp.cpu_count())
    print(f"Using {cpu_count} worker processes")

    total_tried = 0
    next_report = PROGRESS_REPORT

    with mp.Pool(processes=cpu_count, initializer=init_worker,
                 initargs=(iv, ciphertext, target_hmac),
                 maxtasksperchild=MAX_TASKS_PER_CHILD) as pool:

        try:
            # imap_unordered yields results as workers finish batches
            for pw, plaintext, tried in pool.imap_unordered(worker_check, iter_batches(wordlist_file, BATCH_SIZE), chunksize=1):
                total_tried += tried
                if pw:
                    print(f"[+] Password found after {total_tried:,} tries: '{pw}'")
                    print(f"[+] Decrypted plaintext: {plaintext}")
                    
                    pool.terminate() # stop pool
                    return

                # progress report
                if total_tried >= next_report:
                    print(f"[+] {next_report:,} tried...", file=sys.stderr)
                    next_report += PROGRESS_REPORT

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user, terminating workers...")
            pool.terminate()
            return 1
        
        except Exception as e:
            print(f"[!] Worker raised exception: {e}")
            pool.terminate()
            return 1
        
        finally:
            pool.join()

    print("\n[-] Password not found")
    print(f"[-] Total attempts: {total_tried:,}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
