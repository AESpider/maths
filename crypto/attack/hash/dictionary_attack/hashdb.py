#!/usr/bin/env python3
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# Prompt user for a password
print("Enter your password")
password = input(">>> ").encode()

# Create an HMAC object using the password as the key and SHA256
h = HMAC.new(password, digestmod = SHA256)

# Update HMAC with a fixed salt/context string
h.update(b"Fixed_Salt")

# Generate a random 16-byte Initialization Vector (IV)
iv = get_random_bytes(16)

# Generate the AES key by hashing the password with SHA256
key = SHA256.new(password).digest()

# Encrypt the content of "flag.txt" using AES-CBC
c = AES.new(key, AES.MODE_CBC, iv = iv).encrypt(pad(open("flag.txt", "rb").read(), 16))

# Prepare the output dictionary
r = {
  "iv": iv.hex(),     # IV in hex format
  "c": c.hex(),       # Ciphertext in hex format
  "h": h.hexdigest(), # HMAC digest in hex format
}

# Write the JSON-formatted data to "output.json"
open("output.json", "w").write(json.dumps(r))