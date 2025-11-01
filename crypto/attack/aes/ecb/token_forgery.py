#!/usr/bin/env python3
"""
AES-128 ECB token forgery

This script demonstrates how a server that issues JSON tokens encrypted with
AES-ECB can be abused by cutting-and-pasting ciphertext blocks.

Principle:
  1. The server returns AES-ECB(hex(token)) where token = {"login": "X", "role": "guest"}.
  2. In ECB each 16-byte block encrypts independently, so an attacker can register
     chosen usernames to produce ciphertext blocks corresponding to chosen
     plaintext blocks.
  3. By extracting blocks and reassembling them (cut-and-paste), the attacker
     builds a forged token that decrypts to a JSON with "role": "admin".
  4. Submit the forged token to login() which decrypts and parses the JSON.

Usage: python3 token_forgery.py
"""
import json
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# KEY is generated randomly (AES-128)
KEY = get_random_bytes(16)
users = ["AESpider"]
flag = "FLAG{f4k3_f0r_t3st1ng}"

def register(user: str) -> str:
    if user in users:
        return 'User already exists'
    data = b'{"login": "%s", "role": "guest"}' % user.encode()
    token = hexlify(AES.new(KEY, AES.MODE_ECB).encrypt(pad(data, 16))).decode()
    users.append(user)
    return 'You can use this token to access your account : %s' % token

def login(token_hex: str) -> str:
    try:
        ct = unhexlify(token_hex.strip().encode())
        pt = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ct), 16)
        data = json.loads(pt.decode())
        if data['login'] not in users:
            return 'Unknow user'
        if data['login'] == "AESpider" and data['role'] == "admin":
            return 'Hello admin, here is your secret: %s' % flag
        return "Hello %s, you don't have any secret in our database" % data['login']
    except:
        return 'Invalid token !'

def decrypt_raw_block(ct_block: bytes) -> bytes:
    return AES.new(KEY, AES.MODE_ECB).decrypt(ct_block)

if __name__ == "__main__":
    print(f"AES-128 ECB token forgery\n")
    # Goal: produce a token that decrypts to {"login":"AESpider","role":"admin"}.
    # We can register controlled usernames so the server returns tokens whose
    # ciphertext blocks correspond to chosen plaintext blocks, then splice them.

    # 1) Extract B1: first 16 bytes b'{"login" : "AESpi'
    resp1 = register("AESpi")
    tok1 = resp1.split()[-1]
    B1 = unhexlify(tok1)[:16]

    # 2) Extract B2: second block from a crafted username producing
    #     the fragment b'der", "role": "a'
    resp2 = register('XXXXXder", "role": "a') # 16 bytes
    tok2 = resp2.split()[-1]
    B2 = unhexlify(tok2)[16:32]

    # 3) Extract B3: second block from another username producing 
    #     the fragment b'dmin"          }'  (target block 3)
    resp3 = register('XXXXXdmin"          }')   # 16 bytes
    tok3 = resp3.split()[-1]
    B3 = unhexlify(tok3)[16:32]

    # 4) Extract B4: last block containing full PKCS#7 padding 
    #     (e.g. login length 2 => padding block)
    resp4 = register("X"*2)
    tok4 = resp4.split()[-1]
    B4 = unhexlify(tok4)[-16:]

    # Display extracted blocks
    print("Block 0:", B1.hex(), "| raw PT:", decrypt_raw_block(B1))
    print("Block 1:", B2.hex(), "| raw PT:", decrypt_raw_block(B2))
    print("Block 2:", B3.hex(), "| raw PT:", decrypt_raw_block(B3))
    print("Block 3:", B4.hex(), "| raw PT:", decrypt_raw_block(B4))

    # Assemble the malicious token by concatenating the chosen ECB blocks
    forge = B1 + B2 + B3 + B4
    mal_token = forge.hex()
    decrypt_token = decrypt_raw_block(forge).decode()
    print(f"\nMalicious token: {mal_token}")
    print(f"Decrypted      : b'{decrypt_token}'\n")
    
    # Test login with the forged token
    print("Login result:", login(mal_token))
