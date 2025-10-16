#!/usr/bin/env python3
"""
ECB Oracle Attack - Byte-by-byte attack to recover secret
Exploits ECB mode deterministic encryption weakness
"""

import socket
import base64
import string

# Server configuration
HOST = "localhost"
PORT = 1337

def send_message(message):
    """Sends message to server and returns decrypted response"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(message.encode() + b"\n")
        response = s.recv(1024).strip()
        return base64.b64decode(response)

def get_block_size():
    """Detects AES block size by observing ciphertext length changes"""
    initial_length = len(send_message(""))
    
    for i in range(1, 33):
        new_length = len(send_message("A" * i))
        if new_length > initial_length:
            return new_length - initial_length
    
    return None

def get_flag_length(block_size):
    """Detects flag length by observing when padding causes new block"""
    initial_length = len(send_message(""))
    
    for i in range(1, block_size + 1):
        new_length = len(send_message("A" * i))
        if new_length > initial_length:
            return initial_length - i
    
    return None

def recover_flag(block_size, flag_length):
    """Recovers flag byte-by-byte using ECB oracle attack"""
    recovered = ""
    
    for i in range(flag_length):
        # Align target byte to end of block
        padding = "A" * (block_size - (i % block_size) - 1)
        
        # Get reference ciphertext
        reference_block = send_message(padding)[:block_size * ((i // block_size) + 1)]
        
        # Try each possible byte
        for char in string.printable:
            test_message = padding + recovered + char
            test_block = send_message(test_message)[:block_size * ((i // block_size) + 1)]
            
            # Match found
            if test_block == reference_block:
                recovered += char
                print(f"[+] Flag progress: {recovered}")
                break
    
    return recovered

def main():
    print("[*] Starting ECB Oracle Attack...")
    
    # Detect block size
    block_size = get_block_size()
    print(f"[+] AES Block Size: {block_size} bytes")
    
    # Detect flag length
    flag_length = get_flag_length(block_size)
    print(f"[+] Flag Length: {flag_length} bytes")
    
    # Recover the flag
    print("[*] Recovering flag...")
    flag = recover_flag(block_size, flag_length)
    
    print(f"\n[+] Recovered Flag: {flag}")

if __name__ == "__main__":
    main()