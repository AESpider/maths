#!/usr/bin/env python3
"""
HMAC brute forcer
Usage: python3 hmac_bf_simple.py output.txt path/to/wordlist.txt
"""
import json
import sys
import hmac
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <output.json> <path/to/wordlist.txt>")
        sys.exit(1)
    
    # Load target data
    with open(sys.argv[1]) as f:
        data = json.load(f)
    
    iv = bytes.fromhex(data["iv"])
    ciphertext = bytes.fromhex(data["c"])
    target_hmac = data["h"].lower()
    
    print(f"Target HMAC: {target_hmac}")
    
    # Brute force
    tries = 0
    with open(sys.argv[2], 'r', errors='ignore') as wordlist:
        for line in wordlist:
            password = line.rstrip().encode()
    
            if not password:
                continue

            tries += 1
            
            # Check HMAC
            h = HMAC.new(password, b"Fixed_Salt", SHA256)
            if hmac.compare_digest(h.hexdigest(), target_hmac):
                # Found! Decrypt
                key = SHA256.new(password).digest()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                try:
                    plaintext = unpad(cipher.decrypt(ciphertext), 16)
                    print(f"[+] Password found after {tries:,} tries: {password.decode()}")
                    print(f"[+] Decrypted plaintext: {plaintext.decode()}")
                    return
                except:
                    print(f"[!] HMAC match but decrypt failed: {password.decode()}")
                    continue
            
            # Progress every 1M tries
            if tries % 1_000_000 == 0:
                print(f"[+] {tries:,} tries...", file=sys.stderr)
    
    print(f"[-] Password not found after {tries:,} tries")

if __name__ == "__main__":
    main()