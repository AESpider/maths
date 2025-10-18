#!/usr/bin/env python3
import json
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

OUTFILE = "output.json"
SALT_SIZE = 16
NONCE_SIZE = 12  # recommended for GCM
KEY_LEN = 32     # AES-256

# Use scrypt (memory-hard) to derive a 32-byte key
# Note: N=2**16 (65536) is a high-cost parameter
def derive_key(password: bytes, salt: bytes, N=2**14, r=8, p=1):
    """Derive a symmetric key from password using scrypt."""
    master_key = scrypt(password, salt, 32, N=2**16, r=8, p=1)
    
    # Exemple HKDF, here we uses AEAD.
    # enc_key <- HKDF(master_key, 32, salt, SHA256, info=b"ENCRYPT")
    # auth_key <- HKDF(master_key, 32, salt, SHA256, info=b"AUTHENTICATE")
    
    return master_key

def main():
    password = input("Enter your password: ").encode()

    salt = get_random_bytes(SALT_SIZE)   # random salt

    # scrypt parameters used for key derivation
    kdf_params = {"N": 2**14, "r": 8, "p": 1}
    key = derive_key(password, salt, **kdf_params)

    nonce = get_random_bytes(NONCE_SIZE)    # random nonce for GCM

    # Initialize AES in GCM (Authenticated Encryption) mode
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
  
    plaintext = open("flag.txt", "rb").read()

    # GCM is a streaming AEAD: no padding required
    # Encrypt and generate the authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    out = {
        "kdf": "scrypt",
        "kdf_params": kdf_params,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
    }

    # write file with restrictive permissions
    with open(OUTFILE, "w") as f:
        json.dump(out, f)
    os.chmod(OUTFILE, 0o400)
    print(f"Wrote encrypted output to {OUTFILE} (permissions 400).")

if __name__ == "__main__":
    main()